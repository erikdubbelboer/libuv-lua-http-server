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

#include <stdio.h>   /* printf()  */
#include <stdlib.h>  /* exit()    */
#include <assert.h>  /* assert()  */

#include "uv.h"
#include "parson.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "webserver.h"
#include "lru.h"


#define UV_CHECK(x) \
  do { \
    if (x != 0) { \
      printf("%s\n", uv_strerror(uv_last_error(loop))); \
      assert(x != 0); \
      exit(1); \
    } \
  } while (0)


typedef struct lru_entry_s {
  LRU_ENTRY(lru_entry_s) lru;
  char*                  file;
  lua_State*             L;
} lru_entry_t;

static int lru_compare(const lru_entry_t* a, const lru_entry_t* b) {
  return strcmp(a->file, b->file);
}

static void lru_free(lru_entry_t* entry) {
  lua_close(entry->L);
  free(entry->file);
  free(entry);
}

LRU_TYPE(lru_entry_s) scriptlru;

LRU_GENERATE_STATIC(lru_entry_s, lru_compare, lru_free, lru)
    

char* lua_error_handler = 
  "function __error__handler(err)\n"
  "  local i = debug.getinfo(2,'nSl')\n"
  "  if i and i.what == 'C' then\n"
  "    i = debug.getinfo(3,'nSl')\n"
  "  end\n"
  "  if i then\n"
  "    return err ..': '.. i.source .. ': ' .. i.currentline\n"
  "  else\n"
  "    return err\n"
  "  end\n"
  "end\n";


static void write_response(webclient_t* web, int status, size_t size, const char* data) {
  char*  buffer = malloc(size + 4096);
  int    n      = sprintf(
    buffer,
    "HTTP/1.1 %d %s\r\n"
    "Expires: -1\r\n"
    "Cache-Control: no-cache, no-store\r\n"
    "Connection: close\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: text/html\r\n"
    "\r\n",
    status,
    webserver_reason(status),
    size
  );
 
  assert(n < 4096);
  (void)n;  /* For release builds. */

  memcpy(buffer + strlen(buffer), data, size + 1);
 
  webserver_respond(web, buffer, (webserver_free_cb)free);
}


static void error_500(webclient_t* web, const char* message) {
  write_response(web, 500, strlen(message), message);
}


static void on_webserver_handle_common(webclient_t* web, int https) {
  char file[512];

  strncpy(file, web->url, 511);

  char* q = strstr(file, "?");

  if (q) {
    *q = 0;
  }

  if (strstr(file, "../")) {
    error_500(web, "../ is not allowed");
    return;
  }

  if (strcmp(file, "/") == 0) {
    strcpy(file, "/index.lua");
  }

  lru_entry_t  f;
  f.file             = file;
  lru_entry_t* entry = LRU_FIND(lru_entry_s, &scriptlru, &f);

  if (!entry) {
    entry = malloc(sizeof(*entry));
    memset(entry, 0, sizeof(*entry));

    entry->file = strdup(file);
    entry->L    = luaL_newstate();

    luaL_openlibs(entry->L);

    luaL_loadbuffer(entry->L, lua_error_handler, strlen(lua_error_handler), "@error_handler");
    lua_pcall(entry->L, 0, 0, 0);

    lua_getglobal(entry->L, "__error__handler");

    if (luaL_loadfile(entry->L, entry->file + 1)) {
      free(entry);

      error_500(web, lua_tostring(entry->L, -1));

      lua_close(entry->L);
      return;
    }

    LRU_INSERT(lru_entry_s, &scriptlru, entry);
  }


  lua_createtable(entry->L, 0, 6);

  lua_pushstring(entry->L, "ip");
  lua_pushnumber(entry->L, web->ip);
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "url");
  lua_pushstring(entry->L, web->url);
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "method");
  lua_pushstring(entry->L, http_method_str(web->method));
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "cookie");
  lua_pushstring(entry->L, web->cookie);
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "agent");
  lua_pushstring(entry->L, web->agent);
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "referrer");
  lua_pushstring(entry->L, web->referrer);
  lua_rawset    (entry->L, -3);
  lua_pushstring(entry->L, "https");
  lua_pushnumber(entry->L, https);
  lua_rawset    (entry->L, -3);

  lua_setglobal(entry->L, "request");

  lua_pushvalue(entry->L, -1);

  if (lua_pcall(entry->L, 0, 1, -2)) {
    error_500(web, lua_tostring(entry->L, -1));
    return;
  }

  size_t      body_size = lua_strlen  (entry->L, -1);
  const char* body      = lua_tostring(entry->L, -1);

  if (!body) {
    error_500(web, "invalid return value");
    return;
  }

  write_response(web, 200, body_size, body);

  lua_pop(entry->L, 1);
}


static void on_webserver_handle_http(webclient_t* web) {
  on_webserver_handle_common(web, 0);
}


static void on_webserver_handle_https(webclient_t* web) {
  on_webserver_handle_common(web, 1);
}


static void on_webserver_close(webclient_t* web) {
  (void)web;
}


int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("missing config file\n");
    exit(1);
  }

  JSON_Object* config = json_value_get_object(json_parse_file(argv[1]));

  if (!config) {
    printf("could not load config file\n");
    exit(1);
  }
  
  const char* http_ip        = json_object_dotget_string(config, "http.ip"      );
  int         http_port      = json_object_dotget_number(config, "http.port"    );
  const char* https_ip       = json_object_dotget_string(config, "https.ip"     );
  int         https_port     = json_object_dotget_number(config, "https.port"   );
  const char* https_pemfile  = json_object_dotget_string(config, "https.pemfile");
  const char* https_ciphers  = json_object_dotget_string(config, "https.ciphers");

  if (!http_ip  || (http_port  <= 0) ||
      !https_ip || (https_port <= 0) ||
      !https_pemfile || !https_ciphers
  ) {
    printf("invalid config\n");
    exit(1);
  }


  int cachesize = json_object_get_number(config, "cachesize");

  if (cachesize <= 0) {
    cachesize = 64;
  }

  LRU_INIT(&scriptlru, cachesize);


  uv_loop_t* loop = uv_default_loop();


  webserver_t http_server;

  http_server.loop      = loop;
  http_server.handle_cb = on_webserver_handle_http;
  http_server.close_cb  = on_webserver_close;
  
  UV_CHECK(webserver_start(&http_server, http_ip, http_port));


  webserver_t https_server;
  int         err;

  https_server.loop      = loop;
  https_server.handle_cb = on_webserver_handle_https;
  https_server.close_cb  = on_webserver_close;

  if ((err = webserver_start_ssl(&https_server, https_ip, https_port, https_pemfile, https_ciphers)) != 0) {
    printf("%s\n", webserver_error(&https_server));
    exit(1);
  }


  uv_run(loop, UV_RUN_DEFAULT);

  return 0;
}

