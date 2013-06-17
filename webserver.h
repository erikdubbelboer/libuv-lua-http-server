
#ifndef _WEBSERVER_H
#define _WEBSERVER_H


#include <stdint.h>  /* uint32_t */

#include "uv.h"
#include "http_parser.h"


struct webclient_s;

typedef void (*webserver_handle_cb)(struct webclient_s* client);
typedef void (*webserver_close_cb )(struct webclient_s* client);


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

  char url[256];

  uint8_t method;  /* One of the http_method enum members from http_parser.h */

  char cookie  [1024*2];
  char agent   [1024];
  char referrer[1024];

  /* Fields for internal use. */
  struct webio_s* _io;
} webclient_t;


void webserver_respond(webclient_t* client, char* response);
int  webserver_start  (webserver_t* server, const char* ip, int port);
int  webserver_start2 (webserver_t* server, uv_pipe_t* pipe);
int  webserver_stop   (webserver_t* server);

const char* webserver_reason(int status);
const char* webserver_method(int method);


#endif /* _WEBSERVER_H */

