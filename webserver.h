//
// Copyright Erik Dubbelboer. and other contributors. All rights reserved.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

#ifndef _WEBSERVER_H_
#define _WEBSERVER_H_


#include <stdint.h>  /* uint32_t */

#include "uv.h"
#include "http_parser.h"


struct webclient_s;

typedef void (*webserver_handle_cb)(struct webclient_s* client);
typedef void (*webserver_close_cb )(struct webclient_s* client);
typedef void (*webserver_free_cb  )(void* data);


typedef struct webserver_s {
  uv_loop_t*          loop;
  webserver_handle_cb handle_cb;
  webserver_close_cb  close_cb;

  uint32_t connected;  /* Number of connected clients. */

  /* Fields for internal use. */
  uv_stream_t* _handle;
} webserver_t;


typedef struct webclient_s {
  uint32_t ip;

  char url[1024];

  uint8_t method;  /* One of the http_method enum members from http_parser.h */

  char cookie  [1024*2];
  char agent   [1024];
  char referrer[1024];

  /* Fields for internal use. */
  struct webio_s* _io;
} webclient_t;


void webserver_respond(webclient_t* client, char* response, size_t size, webserver_free_cb free_cb);
int  webserver_start  (webserver_t* server, const char* ip, int port);
int  webserver_start2 (webserver_t* server, uv_pipe_t* pipe);
int  webserver_stop   (webserver_t* server);

const char* webserver_reason(int status);


#endif /* _WEBSERVER_H_ */

