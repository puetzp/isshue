# isshue

This is a personal project aimed at discovering how OpenSSH can be leveraged as a secure network transport and authentication tool when building CLI tools.

The `isshue` X.509 certificate management tool is a simple CRUD-like application that is accessed via `ssh` to create X.509 certificates with a CLI. Thus it is suitable for human interaction as well as automated processes, such as clients (virtual machines or init containers) requesting a certificate from `isshue` before starting a HTTPS-only webserver.

The application does not differentiate between the two: From the perspective of `isshue` both type of clients are "users", identified by one or a set of SSH public keys and authorized to request one or many different types of certificates.

A minimal amount of access control ensures that "users" (clients) can only modify certificates they are explicitly allowed to modify, according to the server-side configuration. At the same time all certificates that have been issued by `isshue` are readable by all users, as they are inherently public in nature and there is generally no need to secure those certificates.

## How it works

### Design decisions

The application is explicitly designed to issue certificates for systems in internal networks. In this space trust works different than in the open Internet. There are no DNS challenges, because an internal corporate network with a central DNS server does of course control a given internal domain. Instead the trust model that is deployed by `isshue` aims at authenticating and authorizing individual clients within the network by something they "own", in this case an SSH key.

An SSH session that is successfully created between client and server tells the server that the client is allowed to access the application. An additional step ensures that the SSH public key that authenticated successfully is associated with a specific user that in turn is authorized to request a certificate for a common name (CN).

There is another design decision that is based on how trust works differently in internal networks: Instead of a certificate signing request (CSR) a client passes only a public key to `isshue`, which would normally be one of many parts of a CSR. The client's private key would be used to add a signature to the CSR to tell the server that the client indeed requested a certificate with the exact X.509 attributes in the CSR.

However in this case `isshue` (the certificate authority) decides most of the X.509 attributes that are added to a new certificate, e.g. Subject Alternative Names (SAN), the validity period, as well as Extended Key Usages. Thus most of the information from a CSR would be discarded anyway.

In contrast to signing certificate requests in the open Internet (e.g. via ACME) the process is reduced to:

- authenticate via SSH
- check if client is authorized to request a certificate for `webserver.example.internal`
- use the public key supplied by the user to create a certificate for `webserver.example.internal` with attributes specified by the server/certificate authority
- add the certificate authorities' certificate to the chain (if it is an intermediate CA)
- return the new certificate to the client

### CLI invocations

On the client side the OpenSSH client `ssh` is used to interact with `isshue` on the server side. Since `isshue` is a CLI tool, CLI arguments and options are passed to `ssh` which in turn passes them on to the `isshue` process once its started. For example:

```sh
# Show usage.
$ ssh isshue@example.org help

# Show usage on the `list` subcommand.
$ ssh isshue@example.org help list

# Use the `list` subcommand to show existing certificates. An additional
# argument is used to filter the list by certificates matching a specific CN.
$ ssh isshue@example.org list
$ ssh isshue@example.org list my-app.example.org

# Create a new certificate by passing a public key via ssh. This certificate
# will be marked as the `latest` one for this common name.
$ openssl genpkey -out ec.pem \
    -pkeyopt ec_paramgen_curve:secp384r1 \
    -pkeyopt ec_param_enc:named_curve \
    -algorithm ec

$ openssl pkey -in ec.pem -pubout \
    | ssh isshue@example.org create test.internal \
    | tee test.internal.crt \
    | openssl x509 -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f5:e2:86:fc:45:a4:9f:6d:b9:ec:1b:42:9b:e3:ba:b7
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=issuing-ca.internal
        Validity
            Not Before: Oct 10 14:43:09 2026 GMT
            Not After : Jan  8 14:43:09 2027 GMT
        Subject: CN=test.internal
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:53:af:7f:9e:2a:6f:9d:cb:7f:36:19:15:e5:ad:
                    83:ba:74:44:a3:47:4b:1a:d9:37:34:e9:35:22:ac:
                    83:e9:f9:b9:c2:25:3e:2e:49:77:e9:d2:a1:64:d6:
                    65:81:5a:72:de:1f:5e:d8:2c:63:82:60:60:ba:d8:
                    94:d7:19:04:d6:8e:a2:d9:3a:df:6b:f3:20:16:e2:
                    84:48:5c:82:11:20:1f:ce:51:bd:de:55:5e:fb:78:
                    f6:93:47:80:4c:e4:68
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Subject Alternative Name: critical
                DNS:test.internal, DNS:foo.internal, IP Address:192.168.122.10
            X509v3 Extended Key Usage: critical
                TLS Web Server Authentication, TLS Web Client Authentication
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:66:02:31:00:93:38:49:8d:0f:9a:76:15:87:28:8d:7f:75:
        64:82:a0:04:90:1e:c9:a0:82:a5:3e:8b:58:29:56:39:67:3e:
        77:83:6e:ad:8f:57:e3:b1:ec:d1:b8:6e:f2:3a:79:89:f6:02:
        31:00:f3:26:44:ba:ad:8a:47:7f:c9:7a:55:07:f5:77:a2:70:
        aa:54:8c:0d:a2:53:3d:cb:4c:0d:62:f2:cf:30:4b:5b:c0:9a:
        45:07:22:e9:07:e9:af:80:63:21:0e:a9:c1:d2

# Retrieve the certificate later again.
$ ssh isshue@example.org get test.internal
...

# Clean old certificates (except any marked as `latest`)
$ ssh isshue@example.org clean test.internal
```

On the server side, once `isshue` is installed, a `Match` block inside the OpenSSH configuration forces the SSH server to execute `isshue` whenever a user by the same name authenticates successfully. All arguments supplied by the user to the remote command are passed on to `isshue` which interprets them, just like a local CLI tool would if it were invoked in a local shell instead of via `ssh`. The OpenSSH configuration snippet responsible for running `isshue` looks as follows:

```
# /etc/ssh/sshd_config.d/isshue.conf

Match User isshue
  Banner none
  ForceCommand /usr/bin/isshue
  ExposeAuthInfo yes
  AuthenticationMethods publickey
```

OpenSSH exposes the public key that was used for authentication to `isshue`, so the application is able to associate the public key with a specific application user.

> Caveat: For this to work the public key must be present in both the `AuthorizedKeysFile` and `/etc/isshue/users.yml`. See below for details.

## Building

Once a Rust toolchain is installed via `cargo`, the application and the DEB package can be built with:

```sh
$ cargo install cargo-deb
$ cargo deb -p isshue
```

## Installation

The application is designed to run on systemd-enabled Debian servers only.

1. Install the DEB package on the server:

```sh
$ dpkg -i <path-to-deb>
```

2. Inspect the `sshd` configuration snippet in `/etc/ssh/sshd_config.d/isshue.conf` and tailor it to your needs. Note the comments in the file regarding mandatory directives that are needed for `isshue` to function properly.

> The DEB package also installs `systemd.path` and `systemd.service` units to watch the yet-to-be-created user configuration file at `/etc/isshue/users.yml` and copy the SSH public keys automatically to the `authorized_keys` file used by OpenSSH under the `isshue` user.

## Configuration

### Users

The user configuration of `isshue` is located at `/etc/isshue/users.yml`. It specifies which users are authorized to request certificates when they authenticate with a given SSH key.

Note that `isshue` uses [StrictYAML](https://hitchdev.com/strictyaml) and not standard YAML 1.2.

```yml
---
# A user that is not able to request any certificates, but can read existing certificates.
its-me:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHC/khmASWBIR4fzaoLGuBj5mDRYfcmAvPzEjFc5MK0U some-comment
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMSYg0pI7YAun+ZlMuDSjfP6iZtF7QQ4lBnhWxlW9WpK some@machine
# A complete example of a user that is authorized to request a few different certificates.
someone-else:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqn7H2niImysX3TcHA7w46p9l3Gulq6AhZK1zxtTFa8
  certificates:
    - name: test.internal
      validity: 7
      san:
        dns:
          - alias.internal
        ip:
          - 192.168.122.5
    - name: foobar.internal
```

Users are identified by their SSH keys. Multiple SSH keys can be defined for each user (though the same key cannot be used for multiple users, which will result in silent failure).

User SSH public keys are automatically transferred to an `authorized_keys` file by the `isshue-authorized-keys.{path,service}` systemd units.

Each item in `certificates` can contain the following parameters:

| Path | Description | Default | Optional |
| --- | --- | --- | --- |
| `certificates[].name` | The common name of the new certificate. This is also added as DNS SAN so the certificate can be used for TLS, where the subject is less and less relevant and SANs are primarily used for validation. | | no |
| `certificates[].validity` | The validity period in days. The certificate is valid from the moment it is created and expires after this period. | 90 | yes |
| `certificates[].san` | A mapping containing DNS and IP Subject Alternative Names. | | yes |
| `certificates[].san.dns` | A list of DNS SANs. Each item must follow the same format as `certificates[].name`, i.e. must be a valid common name. | | yes |
| `certificates[].san.ip` | A list of IPv4 or IPv6 addresses to add as IP SANs. | | yes |

### Certificate authority

To sign new certificates `isshue` must control a certificate authority. The application expects two files:

- `/etc/isshue/ca/ca.crt.pem`
- `/etc/isshue/ca/ca.key.pem`

The CA can be either an internal Root CA or an intermediate CA. In either case the private key must no be secured by a passphrase. Otherwise `isshue` will not be able to use it.

See [Generate CA](docs/generate-ca.md) on how to generate certificate authorities and intermediates.
