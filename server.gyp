{
  'variables': {
    'use_openssl%': 'true',
    'shared_openssl%': 'false',
    'shared_zlib%': 'false'
  },

  'targets': [
    {
      'target_name': 'server',
      'type': 'executable',

      'dependencies': [
        'deps/libuv/uv.gyp:libuv',
        'deps/http-parser/http_parser.gyp:http_parser',
        'deps/parson/parson.gyp:parson',
        'deps/luajit/luajit.gyp:libluajit'
      ],

      'sources': [
        'sds.c',
        'webserver.c',
        'main.c'
      ],

      'defines': [
        'ARCH="<(target_arch)"',
        'PLATFORM="<(OS)"'
      ],

      'conditions': [
        [ 'use_openssl=="true"', {
          'defines': [ 'HAVE_OPENSSL=1' ],

          'conditions': [
            [ 'shared_openssl=="false"', {
              'dependencies': [
                'deps/openssl/openssl.gyp:openssl'
              ]
            }]
          ]
        }, {
          'defines': [ 'HAVE_OPENSSL=0' ],
        }]
      ]
    }
  ]
}

