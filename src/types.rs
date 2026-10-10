use serde::{Deserialize, Deserializer};
use std::{fmt, net::IpAddr, ops::Deref, str::FromStr};

/// The verb determines the user action. Different verbs
/// take different options, depending on the context.
/// This mostly resembles the command line arguments parsed
/// by clap.
pub enum Verb {
    Create {
        name: CommonName,
    },
    Clean {
        name: Option<CommonName>,
        force: bool,
    },
    Get {
        name: CommonName,
        digest: Option<Digest>,
    },
    List {
        name: Option<CommonName>,
    },
}

/// A digest is a padded hex representation of a certificate's
/// fingerprint that always consists of 64 hex characters.
/// Knowing this a user-supplied digest can be validated by
/// clap using the type's `FromStr` implementation. This
/// is critical since the input is used to build a filesystem
/// path and invalid input could be disastrous.
#[derive(Clone, Debug, PartialEq)]
pub struct Digest(String);

impl FromStr for Digest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars().count() != 64 {
            anyhow::bail!("digest must be 64 characters in length")
        }

        if let Some(ref c) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
            anyhow::bail!("digest contains invalid character `{}`", c)
        }

        Ok(Self(s.to_lowercase().to_string()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Deref for Digest {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Digest {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A user object typically consists of a set of SSH public keys
/// that associated with the person or machine and a set of
/// certificate attributes that the entity is allowed to request
/// new certificates for.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UserAttributes {
    pub ssh_keys: Vec<SSHKey>,
    #[serde(default)]
    pub certificates: Vec<X509Attributes>,
}

/// This newtype is used to validate SSH public key strings in
/// a very basic way. It mostly strips unimportant parts from
/// a string (such as the key comment) and retains only
/// the key type and the base64-encoded public key itself.
/// Its basic in that the key type and the public key are
/// not validated further.
#[derive(Clone, Debug, PartialEq)]
pub struct SSHKey(String);

impl FromStr for SSHKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            anyhow::bail!("SSH key cannot be an empty string")
        }

        let mut iter = s.split_whitespace();

        let kind = iter.next().ok_or(anyhow::anyhow!(
            "SSH key must contain a key type such as ssh-ed25519"
        ))?;

        let key = iter.next().ok_or(anyhow::anyhow!(
            "SSH key type must be followed by the key itself"
        ))?;

        Ok(Self(format!("{} {}", kind, key)))
    }
}

impl<'de> Deserialize<'de> for SSHKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|s| Self::from_str(&s).map_err(serde::de::Error::custom))
    }
}

impl fmt::Display for SSHKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Deref for SSHKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl SSHKey {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The user object consists of a username and attributes, such
/// as a list of SSH keys and X.509 certificate configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub name: Username,
    pub attributes: UserAttributes,
}

/// This newtype validates usernames. Since usernames are used
/// to build filesystem paths, they should follow a few rules.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Username(String);

impl FromStr for Username {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            anyhow::bail!("username cannot be an empty string")
        }

        if s.chars().count() > 32 {
            anyhow::bail!("username cannot exceed 32 characters")
        }

        if let Some(ref c) = s.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_' || *c == '@')
        }) {
            anyhow::bail!("username contains invalid character `{}`", c)
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for Username {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|s| Self::from_str(&s).map_err(serde::de::Error::custom))
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Deref for Username {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Username {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// This newtype defines rules for common names. The rules are derived
/// from the hostname specification that comes with Debian. They disallow
/// exotic names but allow enough flexibility to cover most use cases, such
/// as common internet domain names.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CommonName(String);

impl FromStr for CommonName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            anyhow::bail!("common name cannot be an empty string")
        }

        if s.chars().count() > 253 {
            anyhow::bail!("common name cannot exceed 253 characters")
        }

        if s.starts_with('-') {
            anyhow::bail!("common name cannot start with a hyphen")
        }

        if let Some(ref c) = s
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_'))
        {
            anyhow::bail!("common name contains invalid character `{}`", c)
        }

        if let Some(ref element) = s
            .split('.')
            .find(|element| !(1..=63).contains(&element.chars().count()))
        {
            anyhow::bail!("dot-separated parts of a common name must be between 1 and 63 characters long, found `{}`", element)
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for CommonName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|s| Self::from_str(&s).map_err(serde::de::Error::custom))
    }
}

impl fmt::Display for CommonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Deref for CommonName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl CommonName {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// X.509 certificates are created according to some internal rules
/// as well as rules that are configurable. This type is used to parse
/// dynamic X.509 attributes from a configuration file, such as the
/// validity period of new certificates and subject alternative
/// names that should be added to them.
/// The most important attribute is the common name (CN). This is
/// used as the certificate's subject as well as the first DNS-SAN.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct X509Attributes {
    pub name: CommonName,
    #[serde(default = "default_validity")]
    pub validity: usize,
    #[serde(default)]
    pub san: SubjectAlternativeNames,
}

fn default_validity() -> usize {
    90
}

/// Subject alternative names can be either DNS names or IPv4/IPv6
/// addresses.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct SubjectAlternativeNames {
    #[serde(default)]
    pub dns: Vec<CommonName>,
    #[serde(default)]
    pub ip: Vec<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, net::IpAddr};

    #[test]
    fn test_digest_success() -> Result<(), anyhow::Error> {
        {
            let input = "8bb64277ad999397300b4c012b22063650d819d9305baf2718523a866036cf67";
            assert_eq!(Digest::from_str(input)?, Digest(input.to_string()));
        }

        {
            let input = "8BB64277AD999397300B4C012B22063650D819D9305BAF2718523A866036CF67";
            assert_eq!(
                Digest::from_str(input)?,
                Digest(input.to_lowercase().to_string())
            );
        }

        Ok(())
    }

    #[test]
    fn test_digest_failure() -> Result<(), anyhow::Error> {
        {
            assert!(Digest::from_str("").is_err());
        }

        {
            let input = "8bb64277ad999397300b4c012b22063650d819d9305baf2718523a866036cf";
            assert!(Digest::from_str(input).is_err());
        }

        {
            let input = "8BB64277AD999397300B4C012B2%063650D819D9305BAF2718523A866036CF67";
            assert!(Digest::from_str(input).is_err());
        }

        Ok(())
    }

    #[test]
    fn test_ssh_key_success() -> Result<(), anyhow::Error> {
        {
            let input = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U some@machine";
            assert_eq!(SSHKey::from_str(input)?, SSHKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U".to_string()));
        }

        {
            let input =
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U";
            assert_eq!(SSHKey::from_str(input)?, SSHKey(input.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_ssh_key_failure() -> Result<(), anyhow::Error> {
        {
            assert!(SSHKey::from_str("").is_err());
        }

        {
            let input = "AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U";
            assert!(SSHKey::from_str(input).is_err());
        }

        Ok(())
    }

    #[test]
    fn test_username_success() -> Result<(), anyhow::Error> {
        {
            let input = "some@machine";
            assert_eq!(Username::from_str(input)?, Username(input.to_string()));
        }

        {
            let input = "some.long.domain.name";
            assert_eq!(Username::from_str(input)?, Username(input.to_string()));
        }

        {
            let input = "email@address.com";
            assert_eq!(Username::from_str(input)?, Username(input.to_string()));
        }

        {
            let input = "some_person";
            assert_eq!(Username::from_str(input)?, Username(input.to_string()));
        }

        {
            let input = "some-person";
            assert_eq!(Username::from_str(input)?, Username(input.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_username_failure() -> Result<(), anyhow::Error> {
        {
            assert!(Username::from_str("").is_err());
        }

        {
            let input = "way-to-many-characters-for-an-eligible-name";
            assert!(Username::from_str(input).is_err());
        }

        {
            let input = "invalid-char-&-in-between";
            assert!(Username::from_str(input).is_err());
        }

        Ok(())
    }

    #[test]
    fn test_common_name_success() -> Result<(), anyhow::Error> {
        {
            let input = "test.internal";
            assert_eq!(CommonName::from_str(input)?, CommonName(input.to_string()));
        }

        {
            let input = "nested.domain.name.internal";
            assert_eq!(CommonName::from_str(input)?, CommonName(input.to_string()));
        }

        {
            let input = "end-entity.legacy_domain.internal";
            assert_eq!(CommonName::from_str(input)?, CommonName(input.to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_common_name_failure() -> Result<(), anyhow::Error> {
        {
            assert!(CommonName::from_str("").is_err());
        }

        {
            assert!(CommonName::from_str("-invalid.internal").is_err());
        }

        {
            assert!(CommonName::from_str("invalid$character.internal").is_err());
        }

        {
            assert!(CommonName::from_str(
                "way-to-long-invalid-subdomain-according-to-some-specification-that-i-chose-to-honor.internal"
            )
            .is_err());
        }

        Ok(())
    }

    #[test]
    fn test_configuration_deserialization_success() -> Result<(), anyhow::Error> {
        {
            let input = r#"
---
me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U some@source
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8
"#;
            let mut expected = HashMap::new();
            expected.insert(
                Username::from_str("me")?,
                UserAttributes {
                    ssh_keys: vec![SSHKey::from_str("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U")?, SSHKey::from_str("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8")?],
                    certificates: vec![],
                },
            );

            assert_eq!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)?,
                expected
            );
        }

        {
            let input = r#"
---
me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U some@source
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8
  certificates:
    - name: foo.internal
    - name: other.internal
      validity: 7
    - name: another.internal
      san:
        dns:
          - alternative-name.internal
        ip:
          - 192.168.122.2
          - 192.168.122.3
"#;
            let mut expected = HashMap::new();
            expected.insert(
                Username::from_str("me")?,
                UserAttributes {
                    ssh_keys: vec![SSHKey::from_str("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U")?, SSHKey::from_str("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8")?],
                    certificates: vec![
                        X509Attributes {
                            name: CommonName::from_str("foo.internal")?,
                            validity: 90,
                            san: SubjectAlternativeNames {
                                dns: vec![],
                                ip: vec![]
                            }
                        },
                        X509Attributes {
                            name: CommonName::from_str("other.internal")?,
                            validity: 7,
                            san: SubjectAlternativeNames {
                                dns: vec![],
                                ip: vec![]
                            }
                        },
                        X509Attributes {
                            name: CommonName::from_str("another.internal")?,
                            validity: 90,
                            san: SubjectAlternativeNames {
                                dns: vec![CommonName::from_str("alternative-name.internal")?],
                                ip: vec![
                                    IpAddr::from_str("192.168.122.2")?,
                                    IpAddr::from_str("192.168.122.3")?,
                                ]
                            }
                        }
                    ],
                },
            );

            assert_eq!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)?,
                expected
            );
        }

        Ok(())
    }

    /// Note that StrictYaml does not allow flow-style YAML such as `[]`
    /// or `{}` to declare empty sequences and maps. StrictYaml also disallows
    /// mapping keys without any values. Such maps should be omitted to signal
    /// that the default value of this map is to be used.
    /// These circumstances must be taken into account when using StrictYaml
    /// for configuration. In this case the bare minimum of configuration
    /// is a user object with at least one SSH key.
    #[test]
    fn test_configuration_deserialization_failure() -> Result<(), anyhow::Error> {
        {
            let input = "";
            assert!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)
                    .is_err()
            );
        }

        {
            let input = "---";
            assert!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)
                    .is_err()
            );
        }

        {
            let input = r#"
---
me:
person:
"#;
            assert!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)
                    .is_err()
            );
        }

        {
            let input = r#"
---
me:
  ssh_keys: []
"#;
            assert!(
                strict_yaml_rust::serde::de::from_str::<HashMap<Username, UserAttributes>>(input)
                    .is_err()
            );
        }

        Ok(())
    }
}
