# Mirage TLSTunnel

To test with default configuration on a standard POSIX host, first ensure you
have a suitable certificate generated in `keys/` (if not, see the
[README](./keys/README.md) to generate a self-signed certificate for testing).

Then, run a plain ol' HTTP server on port 8080 (the default), e.g.,

``` bash
python -m SimpleHTTPServer 8080 # serves up the current directory
```

Finally, configure, build and run the `tlstunnel` unikernel:

``` bash
mirage configure --net=socket -l=\*:debug
make depends && make
sudo ./main.native
```

You should then be able to point a web browser at <https://localhost:4433> to
browse to your HTTP server.

## Acknowledgements

All I did was translate @hannesm's existing
[`tlstunnel`](https://github.com/hannesm/tlstunnel) into a Mirage unikernel. I
won't guarantee that I didn't break anything in passing.
