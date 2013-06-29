
libuv-lua-http-server
=====================

Simple example webserver using libuv and lua.

A simpler http only version is available in the [master](https://github.com/ErikDubbelboer/libuv-lua-http-server) branch.


HTTPS
-----

To generate a pem file for the pemfile option you need to concatenate your private key,
 your certificate and the intermediate certificates up to the top.
```
cp certificate.key pemfile.pem
echo >> pemfile.pem
cat certificate.crt >> pemfile.pem
echo >> pemfile.pem
cat intermediate.pem >> pemfile.pem
```

TODO:
----
* Custom script not found or could not parse handler that could be used to serve static content.
* [SPDY v3](http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3)

