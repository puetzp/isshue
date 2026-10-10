# Generate CA

The following commands can be used to generate a self-signed root CA and then derive an intermediate CA. The latter is then used by `isshue` to sign end-entity server and client certificates. In this example the intermediate CA is not secured by a passphrase, because `isshue` is currently not able to enter a passphrase when the CA is used to sign new certificates.

```
# Create self-signed CA.
openssl req -new \
  -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyform PEM -keyout ca.key.pem \
  -subj "/CN=Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -outform PEM -out ca.crt.pem \
  -x509 -days 1825

# Use self-signed CA to create an "issuing CA" (intermediate CA for signing end-entity certificate requests).
openssl req -new \
  -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyform PEM -keyout issuing-ca.key.pem \
  -subj "/CN=Issuing CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -outform PEM -out issuing-ca.crt.pem \
  -noenc -days 1095 \
  -CA ca.crt.pem -CAkey ca.key.pem
```

