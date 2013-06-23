
libuv-lua-http-server
=====================

Simple example webserver using libuv and lua.

A more complicated https version is available in the [https](https://github.com/ErikDubbelboer/libuv-lua-http-server/tree/https) branch.


HTTPS
-----

To generate a pem file for the pemfile option.
```
cp certificate.key ssl.pem
echo >> ssl.pem
cat certificate.crt >> ssl.pem
```

TODO:
----
* Custom script not found or could not parse handler that could be used to serve static content.

