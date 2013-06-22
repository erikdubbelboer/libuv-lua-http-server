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

#include <stdlib.h>  /* malloc(), free()     */
#include <assert.h>  /* assert()             */
#include <string.h>  /* strncat(), strncpy() */
#include <ctype.h>   /* tolower()            */

#include "http_parser.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "webserver.h"


#ifndef MIN
#define MIN(a,b) (((a)>(b))?(b):(a))
#endif


typedef struct webio_s {
  union {
    uv_pipe_t pipe;
    uv_tcp_t  tcp;
  } handle;

  SSL* ssl;
  BIO* ssl_write;
  BIO* ssl_read;

  webserver_t* server;

  http_parser parser;
  uv_timer_t  timeout;
  
  char*             write_data;
  int               write_active;
  webserver_free_cb write_free;

  int closing;

#ifdef HAVE_KEEP_ALIVE
  int keep_alive;
#endif
  
  char*  header;
  size_t header_size;

  webclient_t client;
} webio_t;


typedef struct webwrite_s {
  webio_t*   io;
  char*      data;
  uv_write_t req;
} webwrite_t;


static http_parser_settings parser_settings;
static int                  ssl_init = 0;


static void after_close_timeout(uv_handle_t* handle) {
  webio_t* io = (webio_t*)handle->data;

  free(io);
}


static void after_close(uv_handle_t* handle) {
  webio_t* io = (webio_t*)handle->data;

  --io->server->connected;

  //BIO_vfree(io->ssl_read);
  //BIO_vfree(io->ssl_write);
  SSL_free(io->ssl);

  io->server->close_cb(&io->client);

  /* We can't just free the io here, we need to close the timer first.
   * (even when it's not active anymore).
   */
  uv_close((uv_handle_t*)&io->timeout, after_close_timeout);
}


static void on_timeout(uv_timer_t* handle, int status) {
  (void)status;

  webio_t* io = (webio_t*)handle->data;

  assert(status == 0);
  (void)status;  /* For release builds. */

  if (!uv_is_closing((uv_handle_t*)&io->handle)) {
    uv_close((uv_handle_t*)&io->handle, after_close);
  }
}


static void after_write(uv_write_t* req, int status) {
  webwrite_t* w = (webwrite_t*)req->data;

  /* status will be set to UV_ECANCELED when the connection
   * is closed durint the write.
   */
  assert((status == 0) || (status != UV_ECANCELED));
  (void)status;  /* For release builds. */

  if (w->data) {
    free(w->data);
  }

  if ((--w->io->write_active == 0) && (w->io->closing)) {
    if (w->io->write_free) {
      w->io->write_free(w->io->write_data);
    }

    w->io->closing = 0;

    /* Stop the write timeout. */
    uv_timer_stop(&w->io->timeout);

    if (!uv_is_closing((uv_handle_t*)req->handle)) {
#ifdef HAVE_KEEP_ALIVE
      if (!w->io->keep_alive) {
#endif
        /* We prefer the client to disconnect so we don't end up with
         * to many socket in the TIME_WAIT state. So set a timeout
         * after which we close the socket.
         */
        uv_timer_start(&w->io->timeout, on_timeout, 2000, 0);
#ifdef HAVE_KEEP_ALIVE
      }
#endif
    }
  }

  free(w);
}


static void flush_write_bio(webio_t* io) {
  char buffer[1024 * 4];
  int  bread;

  while ((bread = BIO_read(io->ssl_write, buffer, sizeof(buffer))) > 0) {
    webwrite_t* w = malloc(sizeof(*w));

    w->io   = io;
    w->data = malloc(bread);
    memcpy(w->data, buffer, bread);

    w->req.data = w;

    uv_buf_t buf = uv_buf_init(w->data, bread);
  
    if (uv_write(&w->req, (uv_stream_t*)&io->handle, &buf, 1, after_write) != 0) {
      free(w);
      free(w->data);

      if (!uv_is_closing((uv_handle_t*)&io->handle)) {
        uv_close((uv_handle_t*)&io->handle, after_close);
      }
    } else {
      ++io->write_active;
    }
  }
}



void webserver_respond(webclient_t* client, char* response, webserver_free_cb free_cb) {
  webio_t* io = client->_io;

  /* Start a write timeout. */
  uv_timer_start(&io->timeout, on_timeout, 2000, 0);

  if (response) {
    io->write_data = response;
    io->write_free = free_cb;

    io->closing = 1;

    if (io->ssl) {
      if (SSL_write(io->ssl, response, strlen(response)) <= 0) {
        free_cb(response);

        if (!uv_is_closing((uv_handle_t*)&io->handle)) {
          uv_close((uv_handle_t*)&io->handle, after_close);
        }
      } else {
        flush_write_bio(io);
      }
    } else {
      webwrite_t* w = malloc(sizeof(*w));

      w->io       = io;
      w->data     = 0;
      w->req.data = w;

      ++io->write_active;

      uv_buf_t buf = uv_buf_init(response, strlen(response));
    
      if (uv_write(&w->req, (uv_stream_t*)&io->handle, &buf, 1, after_write) != 0) {
        free(w);
        free_cb(response);

        if (!uv_is_closing((uv_handle_t*)&io->handle)) {
          uv_close((uv_handle_t*)&io->handle, after_close);
        }
      }
    }
  } else {
    if (!uv_is_closing((uv_handle_t*)&io->handle)) {
      uv_close((uv_handle_t*)&io->handle, after_close);
    }
  }
}


static int on_message_complete(http_parser *p) {
  webio_t* io = (webio_t*)p->data;

#ifdef HAVE_KEEP_ALIVE
  if (io->keep_alive && http_should_keep_alive(p) && (p->http_major > 0) && (p->http_minor > 0)) {
    io->keep_alive = 1;
  }
#endif

  uv_timer_stop(&io->timeout);

  io->server->handle_cb(&io->client);

  return 0;
}


static int on_body(http_parser *p, const char *buf, size_t len) {
  (void)p;
  (void)buf;
  (void)len;

  return 0;
}


static int on_header_value(http_parser *p, const char *buf, size_t len) {
  webio_t* io = (webio_t*)p->data;

  if (io->header) {
    strncat(io->header, buf, MIN(io->header_size - strlen(io->header), len));
  }

  return 0;
}


static int on_header_field(http_parser *p, const char *buf, size_t len) {
  webio_t* io = (webio_t*)p->data;

  /* "If src contains n or more bytes, strncat() writes n+1 bytes to dest."
   * Because of this we need to do sizeof() - 1.
   */

  if (strncasecmp(buf, "cookie", len) == 0) {
    io->header      = io->client.cookie;
    io->header_size = sizeof(io->client.cookie) - 1;
  }
  else if (strncasecmp(buf, "user-agent", len) == 0) {
    io->header      = io->client.agent;
    io->header_size = sizeof(io->client.agent) - 1;
  }
  /* Referrer is misspelled in HTTP. */
  else if (strncasecmp(buf, "referer", len) == 0) {
    io->header      = io->client.referrer;
    io->header_size = sizeof(io->client.referrer) - 1;
  }
  else {
    io->header = 0;
  }

  return 0;
}


static int on_url(http_parser *p, const char *buf, size_t len) {
  webio_t* io = (webio_t*)p->data;

  /* Calculating the mininum length is faster because strncpy pads the destination
   * with zeros until a total of len characters have been written.
   */
  len = MIN(len, sizeof(io->client.url) - 1);
  strncpy(io->client.url, buf, len);
  io->client.url[len] = 0;

  return 0;
}


static int on_message_begin(http_parser *p) {
  webio_t* io = (webio_t*)p->data;

  struct sockaddr_in sockname;
  int                namelen = sizeof(sockname);

  memset(&sockname, 0, sizeof(sockname));

  /* If uv_tcp_getpeername() returns an error the IP will just be set to 0. */
  uv_tcp_getpeername((uv_tcp_t*)&io->handle, (struct sockaddr*)&sockname, &namelen);

  io->client.ip          = sockname.sin_addr.s_addr;
  io->client.method      = p->method;
  io->client.url[0]      = 0;
  io->client.cookie[0]   = 0;
  io->client.agent[0]    = 0;
  io->client.referrer[0] = 0;

#ifdef HAVE_KEEP_ALIVE
  io->keep_alive = 0;
#endif
  
  /* Start a read timer.
   * This will automatically stop the timer that might be running
   * if this is a keep-alive connection.
   */
  uv_timer_start(&io->timeout, on_timeout, 2000, 0);
  
  return 0;
}


static void on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf) {
  webio_t* io = (webio_t*)tcp->data;

  if (nread >= 0) {
    if (io->ssl) {
      BIO_write(io->ssl_read, buf.base, nread);

      if (!SSL_is_init_finished(io->ssl)) {
        SSL_accept(io->ssl);
        flush_write_bio(io);
      } else {
        char buffer[1024 * 4];
        int  bread;

        while ((bread = SSL_read(io->ssl, buffer, sizeof(buffer))) > 0) {
          ssize_t parsed = http_parser_execute(&io->parser, &parser_settings, buffer, bread);

          if (parsed < bread) {
            uv_close((uv_handle_t*)&io->handle, after_close);
            break;
          }
        }
      }
    } else {
      ssize_t parsed = http_parser_execute(&io->parser, &parser_settings, buf.base, nread);

      if (parsed < nread) {
        uv_close((uv_handle_t*)&io->handle, after_close);
      }
    }
  } else {
    uv_close((uv_handle_t*)&io->handle, after_close);
  }

  free(buf.base);
}


static uv_buf_t on_alloc(uv_handle_t* handle, size_t suggested_size) {
  (void)handle;

  char* buf = (char*)malloc(suggested_size);
  return uv_buf_init(buf, suggested_size);
}
  

static void accept_connection(uv_stream_t* handle, webio_t* io) {
  if (uv_accept(handle, (uv_stream_t*)&io->handle)) {
    uv_close((uv_handle_t*)&io->handle, after_close);
  } else {
    uv_timer_init(io->server->loop, &io->timeout);
    uv_timer_start(&io->timeout, on_timeout, 2000, 0);

    http_parser_init(&io->parser, HTTP_REQUEST);

    io->parser.data  = io;
    io->timeout.data = io;
    io->client._io   = io;

    if (io->server->_ssl) {
      io->ssl       = SSL_new(io->server->_ssl);

      if (!io->ssl) {
        uv_close((uv_handle_t*)&io->handle, after_close);
        return;
      }

      io->ssl_write = BIO_new(BIO_s_mem());
      io->ssl_read  = BIO_new(BIO_s_mem());

      SSL_set_bio(io->ssl, io->ssl_read, io->ssl_write);
      SSL_set_accept_state(io->ssl);
    }

    if (uv_read_start((uv_stream_t*)&io->handle, on_alloc, on_read) != 0) {
      uv_close((uv_handle_t*)&io->handle, after_close);
    } else {
      ++io->server->connected;
    }
  }
}


static void on_tcp_connection(uv_stream_t* handle, int status) {
  webserver_t* server = (webserver_t*)handle->data;
  
  assert(status == 0);
  (void)status;  /* For release builds. */

  webio_t* io = (webio_t*)malloc(sizeof(*io));
  memset(io, 0, sizeof(*io));

  uv_tcp_init(server->loop, &io->handle.tcp);

  io->server          = server;
  io->handle.tcp.data = io;

  accept_connection(handle, io);
}


static void on_pipe_connection(uv_pipe_t *handle, ssize_t nread, uv_buf_t buf, uv_handle_type pending) {
  (void)nread;
  
  webserver_t* server = (webserver_t*)handle->data;

  /* Are we receiving something else than a handle? */
  if (pending == UV_UNKNOWN_HANDLE) {
    return;
  }

  /* We ignore buf so free it right away. */
  free(buf.base);

  webio_t* io = (webio_t*)malloc(sizeof(*io));
  memset(io, 0, sizeof(*io));

  uv_pipe_init(server->loop, &io->handle.pipe, 0);

  io->server          = server;
  io->handle.pipe.data = io;

  accept_connection((uv_stream_t*)handle, io);
}


static void start_common() {
  /* It doesn't matter if this happens more then once when starting multiple webservers.
   * No internal state or anything is stored so it will always set the struct to the same state.
   */
  memset(&parser_settings, 0, sizeof(parser_settings));

  parser_settings.on_message_complete = on_message_complete;
  parser_settings.on_body             = on_body;
  parser_settings.on_header_value     = on_header_value;
  parser_settings.on_header_field     = on_header_field;
  parser_settings.on_url              = on_url;
  parser_settings.on_message_begin    = on_message_begin;
}


int webserver_start(webserver_t* server, const char* ip, int port) {
  assert(server->handle_cb);
  assert(server->close_cb );

  start_common();

  server->connected = 0;
  server->_ssl      = 0;
  server->_handle   = (uv_stream_t*)malloc(sizeof(uv_tcp_t));

  memset(server->_handle, 0, sizeof(uv_tcp_t));

  server->_handle->data = server;

  if (uv_tcp_init(server->loop, (uv_tcp_t*)server->_handle) != 0) {
    return 1;
  }

  if (uv_tcp_bind((uv_tcp_t*)server->_handle, uv_ip4_addr(ip, port)) != 0) {
    return 1;
  }

  if (uv_listen(server->_handle, 511, on_tcp_connection) != 0) {
    return 1;
  }

  return 0;
}


int webserver_start2(webserver_t* server, uv_pipe_t* pipe) {
  assert(server->handle_cb);
  assert(server->close_cb );

  start_common();

  server->connected = 0;
  server->_ssl      = 0;
  server->_handle   = (uv_stream_t*)pipe;

  server->_handle->data = server;
  
  if (uv_read2_start(server->_handle, on_alloc, on_pipe_connection) != 0) {
    return 1;
  }

  return 0;
}


static int start_common_ssl(webserver_t* server, const char* chain_file, const char* key_file, const char* cipher_list) {
  if (!ssl_init) {
    SSL_library_init();
  
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();

    ssl_init = 1;
  }

  server->_ssl = SSL_CTX_new(SSLv23_server_method());

  if (!server->_ssl) {
    return 1;
  }

  if (SSL_CTX_use_certificate_chain_file(server->_ssl, chain_file) != 1) {
    return 1;
  }

  if (SSL_CTX_use_PrivateKey_file(server->_ssl, key_file, SSL_FILETYPE_PEM) != 1) {
    return 1;
  }

  if (SSL_CTX_check_private_key(server->_ssl) != 1) {
    return 1;
  }
  
  SSL_CTX_set_verify(server->_ssl, SSL_VERIFY_NONE, NULL); // TODO: No verify!
  SSL_CTX_set_session_cache_mode(server->_ssl, SSL_SESS_CACHE_OFF); // TODO: no caching!

  if (SSL_CTX_set_cipher_list(server->_ssl, cipher_list) != 1) {
    return 1;
  }

  return 0;
}


int webserver_start_ssl(webserver_t* server, const char* ip, int port, const char* chain_file, const char* key_file, const char* cipher_list) {
  assert(server->handle_cb);
  assert(server->close_cb );

  start_common();

  if (start_common_ssl(server, chain_file, key_file, cipher_list) != 0) {
    return 1;
  }

  server->connected = 0;
  server->_handle   = (uv_stream_t*)malloc(sizeof(uv_tcp_t));

  memset(server->_handle, 0, sizeof(uv_tcp_t));

  server->_handle->data = server;

  if (uv_tcp_init(server->loop, (uv_tcp_t*)server->_handle) != 0) {
    return 1;
  }

  if (uv_tcp_bind((uv_tcp_t*)server->_handle, uv_ip4_addr(ip, port)) != 0) {
    return 1;
  }

  if (uv_listen(server->_handle, 511, on_tcp_connection) != 0) {
    return 1;
  }

  return 0;
}


static void after_close_handle(uv_handle_t* handle) {
  free(handle);
}


int webserver_stop(webserver_t* server) {
  if (server->_handle->type == UV_TCP) {
    uv_close((uv_handle_t*)server->_handle, after_close_handle);
    return 0;
  } else {
    return uv_read_stop(server->_handle);
  }
}


const char* webserver_error(webserver_t* server) {
  uv_err_t uverr = uv_last_error(server->loop);

  if (uverr.code != UV_OK) {
    return uv_strerror(uverr);
  }

  unsigned long sslerr = ERR_get_error();

  if (sslerr != 0) {
    return ERR_error_string(sslerr, 0);
  }

  return 0;
}


const char* webserver_reason(int status) {
  switch (status) {
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 102:
      return "Processing";  /* RFC 2518, obsoleted by RFC 4918. */
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 203:
      return "Non-Authoritative Information";
    case 204:
      return "No Content";
    case 205:
      return "Reset Content";
    case 206:
      return "Partial Content";
    case 207:
      return "Multi-Status";  /* RFC 4918 */
    case 300:
      return "Multiple Choices";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Moved Temporarily";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 305:
      return "Use Proxy";
    case 307:
      return "Temporary Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 402:
      return "Payment Required";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 406:
      return "Not Acceptable";
    case 407:
      return "Proxy Authentication Required";
    case 408:
      return "Request Time-out";
    case 409:
      return "Conflict";
    case 410:
      return "Gone";
    case 411:
      return "Length Required";
    case 412:
      return "Precondition Failed";
    case 413:
      return "Request Entity Too Large";
    case 414:
      return "Request-URI Too Large";
    case 415:
      return "Unsupported Media Type";
    case 416:
      return "Requested Range Not Satisfiable";
    case 417:
      return "Expectation Failed";
    case 418:
      return "I\"m a teapot";          /* RFC 2324. */
    case 422:
      return "Unprocessable Entity";   /* RFC 4918. */
    case 423:
      return "Locked";                 /* RFC 4918. */
    case 424:
      return "Failed Dependency";      /* RFC 4918. */
    case 425:
      return "Unordered Collection";   /* RFC 4918. */
    case 426:
      return "Upgrade Required";       /* RFC 2817. */
    case 428:
      return "Precondition Required";  /* RFC 6585. */
    case 429:
      return "Too Many Requests";      /* RFC 6585. */
    case 431:
      return "Request Header Fields Too Large";  /* RFC 6585. */
    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Time-out";
    case 505:
      return "HTTP Version not supported";
    case 506:
      return "Variant Also Negotiates";          /* RFC 2295. */
    case 507:
      return "Insufficient Storage";             /* RFC 4918. */
    case 509:
      return "Bandwidth Limit Exceeded";
    case 510:
      return "Not Extended";                     /* RFC 2774. */
    case 511:
      return "Network Authentication Required";  /* RFC 6585. */
    default:
      return "Unknown";
  }
}

