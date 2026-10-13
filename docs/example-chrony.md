# Requesting a certificate for chrony

As per the [man page](https://manpages.debian.org/latest/chrony/chronyd.8.en.html) `chronyd` is a daemon for synchonization of the system clock. The NTS-KE extension allows clients to retrieve a cookie from a `chrony` server via TLS, in order to validate all subsequent plain NTP packets. This connection is established on port 4460 on the server by default.

To open this port for clients, `chronyd` requires a X.509 certificate and a private key in a location that is still readable for the user after root privileges are dropped. Specifying certificate and private key paths enables the NTS-KE service.

```
# For example: /etc/chrony/conf.d/server.conf

ntsservercert /etc/chrony/tls/server.crt.pem
ntsserverkey /etc/chrony/tls/server.key.pem
```

The rest of the example assumes the following two hosts:

- `ca.internal` where `isshue` is deployed and from which certificates can be requested
- `ntp.internal` where `chronyd` runs with NTS-KE enabled

> It is also assumed that the root user on `ntp.internal` owns a SSH key pair and their `known_hosts` contains the host keys from `ca.internal`, i.e. trust between the two hosts has already been established, which is outside the scope of this example.

## ca.internal

The CA server requires a configuration such as:

```yml
ntp.internal:
  ssh_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMSYg0pI7YAun+ZlMuDSjfP6iZtF7QQ4lBnhWxlW9WpK root@ntp.internal
  certificates:
    - name: ntp.internal
```

The configuration uses the default validity of 90 days and does not add any Subject Alternative Names. It also contains the SSH public key of the root user from `ntp.internal`.

## ntp.internal

When `chronyd` is not supposed to run at all without NTS-KE enabled, the following unit override ensures that the service only starts when a certificate is present:

```
# systemctl edit chrony.service
[Unit]
ConditionPathExists=/etc/chrony/tls/server.crt.pem
```

A static service unit is used to request new certificates:

```
# /etc/systemd/system/chrony-request-certificate.service

[Unit]
Description=Request a X.509 certificate for TLS encryption

[Service]
Type=oneshot
ExecCondition=sh -c '[ ! -s /etc/chrony/tls/server.crt.pem ] || ! openssl x509 -in /etc/chrony/tls/server.crt.pem | openssl x509 -noout -checkend 604800'
ExecStart=mkdir -p /etc/chrony/tls
ExecStart=sh -c '[ -f /etc/chrony/tls/server.key.pem ] || openssl genpkey -out /etc/chrony/tls/server.key.pem -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve -algorithm ec'
ExecStart=sh -c 'openssl pkey -in /etc/chrony/tls/server.key.pem -pubout | ssh isshue@ca.internal create ntp.internal > /etc/chrony/tls/server.crt.pem'
ExecStart=chown root:_chrony /etc/chrony/tls/server.crt.pem
ExecStart=chown root:_chrony /etc/chrony/tls/server.key.pem
ExecStart=chmod 0640 /etc/chrony/tls/server.key.pem
ExecStart=systemctl restart chrony
```

- The unit only executes the steps after `ExecCondition` when this condition returns a zero exit code, i.e. when no non-empty certificate file exists or the certificate is about to expire within the next week.
- The directory is created and a private key generated in case it does not exist.
- The public key is derived from the private key and used to request a certificate for `ntp.internal` from `ca.internal`.
- Permissions on the private key and X.509 certificate are adjusted and `chronyd` is restarted to load the new certificate

A timer unit ensures that expiring certificates are replaced and `chronyd` is restarted automatically:

```
# /etc/systemd/system/chrony-request-certificate.timer

[Unit]
Description=Request a X.509 certificate for TLS encryption

[Timer]
OnCalendar=minutely

[Install]
WantedBy=chrony.service
```

```sh
systemctl enable chrony-request-certificate.timer
systemctl start chrony-request-certificate.timer
```

Running the timer every minute is not strictly needed except in the moment of bootstrapping the service, when no certificate is present. However starting the unit every minute does not hurt either, because the service unit will cancel after running the `ExecCondition` and is thus cheap to run.
