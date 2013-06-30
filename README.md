
libuv-lua-http-server
=====================

Simple example webserver using libuv and lua.

A simpler http only version is available in the [master](https://github.com/ErikDubbelboer/libuv-lua-http-server) branch.

The [https2](https://github.com/ErikDubbelboer/libuv-lua-http-server/tree/https2) branch contains a different implementation of the SSL related code.
The [https1](https://github.com/ErikDubbelboer/libuv-lua-http-server/tree/https1) branch uses uv\_poll and lets OpenSSL handle the IO. While the [https2](https://github.com/ErikDubbelboer/libuv-lua-http-server/tree/https2) branch uses libuv's IO functions.


HTTPS
-----

To generate a pem file for the pemfile option you need to concatenate your private key,
 your certificate and the intermediate certificates up to the top.
```
cp certificate.key ssl.pem
echo >> ssl.pem
cat certificate.crt >> ssl.pem
echo >> ssl.pem
cat intermediate.pem >> ssl.pem
```

TODO:
----
* Custom script not found or could not parse handler that could be used to serve static content.
* [SPDY v3](http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3)

