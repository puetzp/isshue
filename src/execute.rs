use crate::{
    ca, error,
    types::{CommonName, Digest, User},
};
use anyhow::Context;
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey},
};
use std::{
    fmt::Write,
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
    time::SystemTime,
};

/// This function is used to clean old certificates according to these
/// rules:
///
/// * when a common name is supplied, check if the user is allowed to
///   modify certificates match this name and remove only matching
///   certificates
/// * when no common name is supplied, remove all certificates that the
///   user is allowed to modify, but do so only if the --force flag is
///   present.
/// * in any case only remove certificates that are not pointed at
///   by the `latest` symlink, which denotes the newest certificate
///   that is probably still in use.
pub fn clean(
    data_dir: &PathBuf,
    user: &User,
    name: Option<&CommonName>,
    force: bool,
) -> Result<(), anyhow::Error> {
    fn clean(directory: &PathBuf) -> Result<(), anyhow::Error> {
        let latest = {
            let path = directory.join("latest");
            fs::read_link(&path).context(format!("failed to read symlink `{}`", path.display()))?
        };

        for entry in fs::read_dir(&directory)
            .context(format!(
                "failed to read directory `{}`",
                directory.display()
            ))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_ok_and(|ftype| ftype.is_file()))
        {
            if entry.path() != latest {
                fs::remove_file(&entry.path()).context(format!(
                    "failed to remove file `{}`",
                    entry.path().display()
                ))?;
            }
        }

        Ok(())
    }

    if let Some(name) = name {
        if !user
            .attributes
            .certificates
            .iter()
            .any(|item| item.name == *name)
        {
            anyhow::bail!(error::UserError::new("permission denied".to_string()));
        }

        let directory = data_dir.join(name.as_str());

        clean(&directory).context(format!(
            "failed to remove certificates from directory `{}`",
            directory.display()
        ))?;
    } else {
        if !force {
            anyhow::bail!(error::UserError::new(
                "specify a common name or use the --force flag to clean all certificates"
                    .to_string()
            ))
        }

        let names = user
            .attributes
            .certificates
            .iter()
            .map(|item| &item.name)
            .collect::<Vec<&CommonName>>();

        for name in names {
            let directory = data_dir.join(name.as_str());

            clean(&directory).context(format!(
                "failed to remove certificates from directory `{}`",
                directory.display()
            ))?;
        }
    }

    Ok(())
}

/// Get a PEM-encoded end-entity certificate. By default the newest
/// certificate is returned, unless a digest is supplied, in which
/// case the certificate matching this digest is returned instead.
/// Since X.509 certificates are public in nature, user permissions
/// do not need to be checked here.
pub fn get(
    data_dir: &PathBuf,
    name: &CommonName,
    digest: Option<&Digest>,
) -> Result<(), anyhow::Error> {
    let path = if let Some(digest) = digest {
        data_dir.join(name.as_str()).join(digest.as_str())
    } else {
        data_dir.join(name.as_str()).join("latest")
    };

    let certificate = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                anyhow::bail!(error::UserError::new("unknown certificate".to_string()));
            } else {
                anyhow::bail!(error)
            }
        }
    };

    println!("{}", certificate);

    Ok(())
}

/// Create a new certificate based on the user configuration, a
/// common name supplied via command line and a PEM-encoded public key
/// supplied via standard input.
/// The public key is parsed before a new certificate is issued according
/// to these rules:
///
/// * the size of an EC key must be at least 256 bits
/// * the size of an RSA key must be at least 4096 bits.
///
/// After creating the certificate according to the rules above and
/// the hardcoded attributes set by the certificate authority, the
/// certificate is written to the filesystem using the digest
/// (sha256 checksum of the whole certificate) as file name.
/// The `latest` symlink denotes the newest certificate matching
/// a given common name. As such the symlink is changed to point
/// to the digest of the new certificate.
///
/// The new certificate is then printed to standard output so the
/// user can save it on their side. The certificate may contain
/// the certificate authority certificate if the CA determines it
/// must be included in the chain.
pub fn create(data_dir: &PathBuf, user: &User, name: &CommonName) -> Result<(), anyhow::Error> {
    let ca = ca::CA::new()?;

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    let public_key = PKey::public_key_from_pem(&input)
        .context("failed to parse PEM-encoded public key from standard input")?;

    match public_key.id() {
        Id::RSA => {
            if public_key.bits() < 4096 {
                anyhow::bail!(error::UserError::new(
                    "RSA key size must be at least 4096 bits".to_string()
                ))
            }
        }
        Id::EC => {
            if public_key.bits() < 256 {
                anyhow::bail!(error::UserError::new(
                    "EC key size must be at least 256 bits".to_string()
                ))
            }
        }
        _ => anyhow::bail!(error::UserError::new(
            "key type must be one of [RSA, EC]".to_string()
        )),
    }

    let certificate = ca
        .create(&public_key, user, name)
        .context("failed to create new x509 certificate from public key")?;

    let digest = certificate
        .digest(MessageDigest::sha256())?
        .iter()
        .map(|digit| format!("{:02x}", digit))
        .collect::<String>();

    let mut bytes = certificate.to_pem()?;

    if !ca.is_self_signed() {
        bytes.append(&mut ca.certificate.to_pem()?);
    }

    {
        let dir = data_dir.join(name.as_str());

        if !dir.try_exists().context(format!(
            "failed to check if directory `{}` exists",
            dir.display()
        ))? {
            fs::create_dir(&dir)
                .context(format!("failed to create directory `{}`", dir.display()))?;
        }

        let certificate_path = dir.join(&digest);

        fs::write(&certificate_path, &bytes).context(format!(
            "failed to write new certificate to `{}`",
            certificate_path.display()
        ))?;

        let link_path = dir.join("latest");

        if link_path.try_exists().context(format!(
            "failed to check if symlink `{}` exists",
            link_path.display()
        ))? {
            fs::remove_file(&link_path).context(format!(
                "failed to remove symlink `{}`",
                link_path.display()
            ))?;
        }

        std::os::unix::fs::symlink(&certificate_path, &link_path).context(format!(
            "failed to create symlink `{}` to `{}`",
            link_path.display(),
            certificate_path.display()
        ))?;
    }

    let output = String::from_utf8(bytes)?;

    println!("{}", output);

    Ok(())
}

/// Print a list of certificates to standard output according to
/// the following rules:
///
/// * when a common name is supplied by the user, only print
///   certificates matching this common name, otherwise print
///   information about all certificates.
/// * highlight the newest certificate for a given common name
///   (`latest`) with a `*`.
/// * specify when the certificate was created
/// * print the digest which is used in other operations, such as
///   `get`
///
/// Since the output of this function is meant for human interaction
/// the output is printed as a table instead of a machine-readable
/// format such as YAML or JSON.
pub fn list(data_dir: &PathBuf, name: Option<&CommonName>) -> Result<(), anyhow::Error> {
    fn format_ctime(ctime: SystemTime) -> Result<String, anyhow::Error> {
        let duration = SystemTime::now().duration_since(ctime)?.as_secs();

        let s = if duration > 60 * 60 * 24 {
            format!("{} days ago", duration / 60 / 60 / 24)
        } else if duration > 60 * 60 {
            format!("{} hours ago", duration / 60 / 60)
        } else if duration > 60 {
            format!("{} minutes ago", duration / 60)
        } else {
            format!("{} seconds ago", duration)
        };

        Ok(s)
    }

    struct Item {
        is_latest: bool,
        name: CommonName,
        digest: String,
        created: String,
    }

    let mut items: Vec<Item> = vec![];

    #[derive(Debug, Default)]
    struct Widths {
        latest: usize,
        name: usize,
        digest: usize,
        created: usize,
    }

    impl Widths {
        fn adjust(&mut self, item: &Item) {
            if item.name.len() > self.name {
                self.name = item.name.len();
            }

            if item.digest.len() > self.digest {
                self.digest = item.digest.len();
            }

            if item.created.len() > self.created {
                self.created = item.created.len();
            }
        }
    }

    let mut widths = Widths {
        latest: 6,
        ..Default::default()
    };

    for directory in fs::read_dir(&data_dir)
        .context(format!("failed to read directory `{}`", data_dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|ftype| ftype.is_dir()))
        .filter(|entry| {
            name.is_none_or(|name| {
                entry
                    .file_name()
                    .into_string()
                    .is_ok_and(|s| s == name.as_str())
            })
        })
    {
        let path = directory.path();

        let common_name =
            CommonName::from_str(&directory.file_name().into_string().map_err(|_| {
                anyhow::anyhow!(
                    "failed to convert file name of directory `{}` to string",
                    path.display()
                )
            })?)?;

        for entry in fs::read_dir(&path)
            .context(format!("failed to read directory `{}`", path.display()))?
            .filter_map(|entry| entry.ok())
        {
            let path = entry.path();

            let file_name = entry.file_name().into_string().map_err(|_| {
                anyhow::anyhow!(
                    "failed to convert file name of file `{}` to string",
                    path.display()
                )
            })?;

            if entry.file_type().is_ok_and(|ftype| ftype.is_symlink()) && file_name == "latest" {
                let digest = fs::read_link(&path)
                    .context(format!("failed to traverse symlink `{}`", path.display()))?
                    .file_name()
                    .and_then(|fname| fname.to_str())
                    .ok_or(anyhow::anyhow!(
                        "failed to determine file name of file behind symlink `{}`",
                        path.display()
                    ))?
                    .to_string();

                if let Some(item) = items.iter_mut().find(|item| item.digest == digest) {
                    item.is_latest = true;
                    continue;
                }

                let metadata = fs::metadata(&path).context(format!(
                    "failed to query metadata while traversing symlink `{}`",
                    path.display()
                ))?;

                let ctime = metadata.created().context(format!(
                    "failed to access creation timestamp of file behind symlink `{}`",
                    path.display()
                ))?;

                let item = Item {
                    is_latest: true,
                    name: common_name.clone(),
                    digest,
                    created: format_ctime(ctime)?,
                };

                widths.adjust(&item);

                items.push(item);
            } else if entry.file_type().is_ok_and(|ftype| ftype.is_file())
                && !items.iter().any(|item| item.digest == file_name)
            {
                let metadata = entry.metadata().context(format!(
                    "failed to query metadata of file `{}`",
                    path.display()
                ))?;

                let ctime = metadata.created().context(format!(
                    "failed to access creation timestamp of file `{}`",
                    path.display()
                ))?;

                let item = Item {
                    is_latest: false,
                    name: common_name.clone(),
                    digest: file_name,
                    created: format_ctime(ctime)?,
                };

                widths.adjust(&item);

                items.push(item);
            }
        }
    }

    items.sort_by(|a, b| a.name.cmp(&b.name).then(b.is_latest.cmp(&a.is_latest)));

    let mut output = String::new();

    if items.len() > 0 {
        write!(&mut output, "{:1$}", "LATEST", widths.latest + 2)?;
        write!(&mut output, "{:1$}", "COMMON NAME", widths.name + 2)?;
        write!(&mut output, "{:1$}", "DIGEST", widths.digest + 2)?;
        write!(&mut output, "{:1$}", "CREATED", widths.created + 2)?;

        for item in items {
            writeln!(&mut output)?;

            if item.is_latest {
                write!(&mut output, "{0:1$}", "*", widths.latest + 2)?;
            } else {
                write!(&mut output, "{0:1$}", "", widths.latest + 2)?;
            }

            write!(&mut output, "{0:1$}", item.name, widths.name + 2)?;
            write!(&mut output, "{0:1$}", item.digest, widths.digest + 2)?;
            write!(&mut output, "{0:1$}", item.created, widths.created + 2)?;
        }

        println!("{}", output);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // TODO: Figure out a way to unit-test the functions in this module.
}
