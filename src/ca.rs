use crate::{
    error,
    types::{CommonName, User},
};
use anyhow::Context;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509Name, X509,
    },
};
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

/// The certificate authority consists of a X.509 certificate
/// and a private key.
#[derive(Debug)]
pub struct CA {
    pub certificate: X509,
    pub private_key: PKey<Private>,
}

impl CA {
    /// Parse the PEM-encoded certificate and private key from a
    /// specific location in the filesystem.
    pub fn new() -> Result<Self, anyhow::Error> {
        let private_key = {
            let path = Path::new("/etc/isshue/ca/ca.key.pem");

            let bytes = fs::read(&path).context(format!(
                "failed to read private key file `{}`",
                path.display()
            ))?;

            PKey::private_key_from_pem(&bytes).context(format!(
                "failed to parse PEM-encoded private key from file `{}`",
                path.display(),
            ))?
        };

        let certificate = {
            let path = Path::new("/etc/isshue/ca/ca.crt.pem");

            let bytes = fs::read(&path).context(format!(
                "failed to read certificate file `{}`",
                path.display()
            ))?;

            X509::from_pem(&bytes).context(format!(
                "failed to parse PEM-encoded certificate from file `{}`",
                path.display(),
            ))?
        };

        Ok(Self {
            certificate,
            private_key,
        })
    }

    /// Check if the certificate is self-signed. The easiest way
    /// to do so is comparing the issuer and subject fields.
    /// Knowing if the certificate authority is self-signed is
    /// required to decide if the certificate needs to be appended
    /// to end-entity certificates.
    pub fn is_self_signed(&self) -> bool {
        self.certificate.issuer_name_hash() == self.certificate.subject_name_hash()
    }

    /// This function creates a new X.509 certificate. It requires
    /// the following inputs:
    ///
    /// * a public key supplied by the user via standard input
    /// * the user object from the server configuration
    /// * the common name for which the certificate is issued
    ///
    /// These three inputs are used to create a certificate by
    /// these rules:
    ///
    /// * check if the user is allowed to retrieve a new certificate
    ///   for the given common name
    /// * build the certificate according to internal rules and
    ///   the configuration from the user object
    /// * set the certificate's public key section to the public
    ///   key data supplied by the user
    /// * sign the certificate using the CA's private key
    pub fn create(
        &self,
        public_key: &PKey<Public>,
        user: &User,
        name: &CommonName,
    ) -> Result<X509, anyhow::Error> {
        let entry = user
            .attributes
            .certificates
            .iter()
            .find(|item| item.name == *name)
            .ok_or(anyhow::anyhow!(
                "failed to find entry for common name `{}` in configuration of user `{}`",
                name,
                user.name
            ))
            .context(error::UserError::new("permission denied".to_string()))?;

        let mut builder = X509::builder()?;

        builder.set_issuer_name(self.certificate.subject_name())?;

        {
            let mut subject_name = X509Name::builder()?;

            subject_name.append_entry_by_nid(Nid::COMMONNAME, name.as_str())?;

            builder.set_subject_name(&subject_name.build())?;
        }

        builder.set_pubkey(&public_key)?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let not_before = Asn1Time::from_unix(now.as_secs() as i64)?;

        builder.set_not_before(&not_before)?;

        let not_after = Asn1Time::from_unix(
            (now + Duration::from_hours(entry.validity as u64 * 24)).as_secs() as i64,
        )?;

        builder.set_not_after(&not_after)?;

        builder.append_extension(BasicConstraints::new().critical().build().unwrap())?;

        builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .non_repudiation()
                .build()
                .unwrap(),
        )?;

        {
            let mut subject_alt_name = SubjectAlternativeName::new();

            subject_alt_name.critical().dns(name.as_str());

            for san in &entry.san.dns {
                subject_alt_name.dns(san.as_str());
            }

            for san in &entry.san.ip {
                subject_alt_name.ip(&san.to_string());
            }

            builder.append_extension(
                subject_alt_name
                    .build(&builder.x509v3_context(Some(&self.certificate), None))
                    .unwrap(),
            )?
        }

        builder.append_extension(
            ExtendedKeyUsage::new()
                .critical()
                .server_auth()
                .client_auth()
                .build()
                .unwrap(),
        )?;

        builder.set_version(2)?;

        {
            let mut bn = BigNum::new_secure()?;

            bn.rand(128, MsbOption::MAYBE_ZERO, true)?;

            let integer = Asn1Integer::from_bn(&bn)?;

            builder.set_serial_number(&integer)?;
        }

        builder.sign(&self.private_key, MessageDigest::sha256())?;

        Ok(builder.build())
    }
}
