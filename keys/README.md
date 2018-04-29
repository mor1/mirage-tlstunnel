# Generating Secrets for Mirage Build

To generate self-signed cert for testing:

```bash
openssl genrsa -out server.key 2048
openssl rsa -in server.key -out server.key
openssl req -sha256 -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -sha256 -days 30 -in server.csr -signkey server.key -out server.crt
cat server.crt server.key > server.pem
```

...will create the certificate `server.pem` and the key `server.key`, the
defaults expected by `X509.certificate keys ``Default` after being crunched to
a `KV_RO`.
