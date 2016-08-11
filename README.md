# Mirage TLSTunnel

## Notes

* to generate self-signed cert for testing:

> mkdir keys && cd keys
> openssl req -new -key server.key -out server.req
> openssl x509 -req -days 30 -in request.pem -signkey server.key -out server.pem
> openssl x509 -req -days 30 -in server.req -signkey server.key -out server.pem

...will create the certificate `server.pem` and the key `server.key` in
subdirectory `keys`, the defaults expected by `X509.certificate keys ``Default`
after being crunched to a `KV_RO`.
