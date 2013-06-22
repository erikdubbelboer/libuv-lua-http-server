{
  'targets': [
    {
      'target_name': 'server',
      'type': 'executable',

      'dependencies': [
        'deps/libuv/uv.gyp:libuv',
        'deps/http-parser/http_parser.gyp:http_parser',
        'deps/parson/parson.gyp:parson',
        'deps/luajit/luajit.gyp:libluajit',
        'deps/openssl/openssl.gyp:openssl'
      ],

      'sources': [
        'webserver.c',
        'main.c'
      ],

      'defines': [
        'ARCH="<(target_arch)"',
        'PLATFORM="<(OS)"'
      ]
    }
  ]
}

