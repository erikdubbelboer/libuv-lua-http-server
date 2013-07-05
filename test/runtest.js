
var cp   = require('child_process');
var http = require('http');

var server = cp.spawn(__dirname + '/../server', [__dirname + '/config.json']);

var expectshutdown = false;

server.on('close', function(code) {
  if (code != 0) {
    console.log('FAIL: server stopped with code ' + code);
    process.exit(1);
  } else if (!expectshutdown) {
    console.log('FAIL: server stopped unexpected');
    process.exit(1);
  } else {
    console.log('PASSED: done');
    process.exit(0);
  }
});
server.stdout.on('data', function(data) {
  console.log('SERVER: ' + data);
});
server.stderr.on('data', function(data) {
  console.log('SERVER: ' + data);
});


setTimeout(function() {
  test1();
}, 100);


function test1() {
  var options = {
    hostname: '0.0.0.0',
    port    : 9999,
    path    : '/test/headers.lua',
    agent   : false,
    headers : {
      'User-Agent': 'test',
      'Cookie'    : 'test=1'
    }
  };

  http.request(options, function(response) {
    if (response.statusCode != 200) {
      console.log('FAIL: headers.lua returned code ' + response.statusCode);
    }

    var body = '';

    response.on('data', function(chunk) {
      body += chunk.toString('ascii');
    });
    response.on('end', function() {
      if (body.indexOf('ip: 16777343') == -1) {
        console.log('FAIL: headers.lua body did not contain ip');
      }
      if (body.indexOf('url: /test/headers.lua') == -1) {
        console.log('FAIL: headers.lua body did not contain url');
      }
      if (body.indexOf('agent: test') == -1) {
        console.log('FAIL: headers.lua body did not contain agent');
      }
      if (body.indexOf('cookie: test=1') == -1) {
        console.log('FAIL: headers.lua body did not contain cookie');
      }

      test2();
    });
  }).end();
}


function test2() {
  var options = {
    hostname: '0.0.0.0',
    port    : 9999,
    path    : '/test/shutdown.lua',
    agent   : false
  };

  expectshutdown = true;

  http.request(options, function(response) {
    if (response.statusCode != 200) {
      console.log('FAIL: shutdown.lua returned code ' + response.statusCode);
    }

    response.on('data', function(chunk) {
      // Ignore.
    });
    response.on('end', function() {
      setTimeout(function() {
        console.log('FAIL: shutdown.lua did not shut down the server');
        process.exit(1);
      }, 200);
    });
  }).end();
}

