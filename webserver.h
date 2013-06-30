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


#ifndef WEBSERVER_READ_TIMEOUT
# define WEBSERVER_READ_TIMEOUT      (10*1000)
#endif
#ifndef WEBSERVER_WRITE_TIMEOUT
# define WEBSERVER_WRITE_TIMEOUT     (10*1000)
#endif
#ifndef WEBSERVER_KEEPALIVE_TIMEOUT
# define WEBSERVER_KEEPALIVE_TIMEOUT (5 *1000)
#endif


struct webserver_s;
struct webclient_s;

typedef void (*webserver_handle_cb)(struct webclient_s* client);
typedef void (*webserver_close_cb )(struct webclient_s* client);
typedef void (*webserver_free_cb  )(void* buffer);
typedef void (*webserver_stop_cb  )(struct webserver_s* server);
typedef void (*webserver_error_cb )(const char* error);


typedef struct webserver_s {
  uv_loop_t* loop;

  /* This callback will be called when a new request has arrived. */
  webserver_handle_cb handle_cb;

  /* This callback will be called when the connection 
   * to the client is closed. The callback can be called
   * for connections that haven't seen a handle_cb yet.
   */
  webserver_close_cb  close_cb;

  /* This callback will be called on an error. */
  webserver_error_cb  error_cb;
  
  /* This is called when the server has closed it's listening socket. */
  webserver_stop_cb   stop_cb;


  /* Readonly: */
  int connected;  /* Number of connected clients. */

  /* Fields for internal use: */
  uv_stream_t*       _handle;
#if HAVE_OPENSSL
  struct ssl_ctx_st* _ssl;
#endif
  int                _closing;
} webserver_t;


typedef struct webclient_s {
  uint32_t ip;

  char url[1024];

  uint8_t method;   /* One of the http_method enum members from http_parser.h */
  uint8_t version;  /* HTTP version, (major * 10) + minor                     */

  char cookie  [1024*2];
  char agent   [1024];
  char referrer[1024];

  webserver_t* server;

  /* Fields for internal use. */
  struct webio_s* _io;
} webclient_t;


/**
 * Send back a response to the client.
 *
 * timeout: Write timeout, 0 means WEBSERVER_WRITE_TIMEOUT.
 *          It is advised to set a higher timeout when writing large amounts of data.
 */
void        webserver_respond   (webclient_t* client, char* response, size_t size, webserver_free_cb free_cb, uint32_t timeout);
int         webserver_start     (webserver_t* server, const char* ip, int port);
int         webserver_start2    (webserver_t* server, uv_pipe_t* pipe);
int         webserver_stop      (webserver_t* server);
const char* webserver_error     (webserver_t* server);

#if HAVE_OPENSSL
/**
 * ciphers: See http://www.openssl.org/docs/apps/ciphers.html#CIPHER_LIST_FORMAT
 *          Recommended is: "ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH"
 */
int         webserver_start_ssl (webserver_t* server, const char* ip, int port, const char* pemfile, const char* ciphers);
int         webserver_start_ssl2(webserver_t* server, uv_pipe_t* pipe, const char* pemfile, const char* ciphers);
#endif 

const char* webserver_reason(int status);


#endif /* _WEBSERVER_H_ */

