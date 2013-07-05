/*
 * Copyright Erik Dubbelboer. and other contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>          /* printf()    */
#include <stdlib.h>         /* exit()      */
#include <assert.h>         /* assert()    */
#if !defined(_MSC_VER)
# include <sys/resource.h>  /* getrlimit() */
#endif

#include "uv.h"
#include "parson.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "sds.h"
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

static uv_loop_t* loop;

static webserver_t server_http;
static webserver_t server_https;

static uv_timer_t print;
static uint32_t   handled = 0;
    

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


static void http_error(webclient_t* web, int status, const char* message) {
  size_t size   = strlen(message);
  char*  buffer = (char*)pool_malloc(&web->pool, 4096 + size);
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

  /* There will always be enough room for this. */
  strcat(buffer, message);

  webserver_respond(web, buffer, n + size, 0);
}


static int clua_shutdown(lua_State* L) {
  (void)L;

  if (server_http.loop) {
    webserver_stop(&server_http);
  }
  if (server_https.loop) {
    webserver_stop(&server_https);
  }
  
  UV_CHECK(uv_timer_stop(&print));

  return 0;
}


static void on_webserver_handle(webclient_t* web, int https) {
  ++handled;

  char file[512];

  strncpy(file, web->url, 511);

  char* q = strstr(file, "?");

  if (q) {
    *q = 0;
  }

  if (strstr(file, "../")) {
    http_error(web, 500, "../ is not allowed");
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
      http_error(web, 500, lua_tostring(entry->L, -1));

      lua_close(entry->L);

      free(entry->file);
      free(entry);
      return;
    }

    lua_pushcfunction(entry->L, clua_shutdown);
    lua_setglobal(entry->L, "shutdown");

    LRU_INSERT(lru_entry_s, &scriptlru, entry);
  }


  /* The stack should be of size 2 with the
   * 1e item __error__handler and the
   * 2e item the script loaded by luaL_loadfile.
   */
  assert(lua_gettop(entry->L) == 2);
  assert(lua_isfunction(entry->L, 1));
  assert(lua_isfunction(entry->L, 2));


  /* Push the request table on the stack. */
  lua_createtable(entry->L, 0, 6);

  /* Fill it. */
  lua_pushliteral(entry->L, "ip");
  lua_pushnumber (entry->L, web->ip);
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "url");
  lua_pushstring (entry->L, web->url);
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "method");
  lua_pushstring (entry->L, http_method_str(web->method));
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "https");
  lua_pushnumber (entry->L, https);
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "cookie");
  lua_pushstring (entry->L, web->cookie);
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "agent");
  lua_pushstring (entry->L, web->agent);
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "referrer");
  lua_pushstring (entry->L, web->referrer);
  lua_rawset     (entry->L, -3);

  /* Assign it to a global variable. */
  lua_setglobal(entry->L, "request");
  
  
  /* Push the response table on the stack. */
  lua_createtable(entry->L, 0, 6);
  
  lua_pushliteral(entry->L, "headers");

  /* Push the headers table on the stack. */
  lua_createtable(entry->L, 0, 6);
  
  lua_pushliteral(entry->L, "Content-Type");
  lua_pushliteral(entry->L, "text/html");
  lua_rawset     (entry->L, -3);

  /* Assign it to the headers field. */
  lua_rawset    (entry->L, -3);
  
  lua_pushliteral(entry->L, "body");
  lua_pushliteral(entry->L, "");
  lua_rawset     (entry->L, -3);
  lua_pushliteral(entry->L, "status");
  lua_pushnumber (entry->L, 200);
  lua_rawset     (entry->L, -3);

  /* Assign it to a global variable. */
  lua_setglobal(entry->L, "response");


  /* Duplicate the main script function on the stack.
   * (the one pushed by luaL_loadfile).
   * We need to do this because lua_pcall replaces the
   * function with the return value.
   */
  lua_pushvalue(entry->L, 2);

  if (lua_pcall(entry->L, 0, 0, 1)) {
    http_error(web, 500, lua_tostring(entry->L, -1));
  
    /* Return the stack to the starting state. */
    lua_pop(entry->L, lua_gettop(entry->L) - 2);
    return;
  }

  lua_getglobal(entry->L, "response");

  if (!lua_istable(entry->L, -1)) {
    http_error(web, 500, "global response is not a table");
  
    /* Return the stack to the starting state. */
    lua_pop(entry->L, lua_gettop(entry->L) - 2);
    return;
  }

  /* The the body. */
  lua_pushliteral(entry->L, "body");
  lua_gettable(entry->L, -2);

  if (!lua_isstring(entry->L, -1)) {
    http_error(web, 500, "response.body is not a string");
  
    /* Return the stack to the starting state. */
    lua_pop(entry->L, lua_gettop(entry->L) - 2);
    return;
  }

  size_t      body_size = lua_strlen  (entry->L, -1);
  const char* body      = lua_tostring(entry->L, -1);
  
  /* Pop the body of the stack. */
  lua_pop(entry->L, 1);
  
  
  /* Get the status code. */
  lua_pushliteral(entry->L, "status");
  lua_gettable(entry->L, -2);

  if (!lua_isnumber(entry->L, -1)) {
    http_error(web, 500, "response.status is not a number");
  
    /* Return the stack to the starting state. */
    lua_pop(entry->L, lua_gettop(entry->L) - 2);
    return;
  }

  int status = lua_tonumber(entry->L, -1);

  /* Pop the status of the stack. */
  lua_pop(entry->L, 1);
  

  sds headers = sdsempty();

  lua_pushliteral(entry->L, "headers");
  lua_gettable(entry->L, -2);
  
  /* Push the first key. */
  lua_pushnil(entry->L);

  while (lua_next(entry->L, -2) != 0) {
    const char* key   = lua_tostring(entry->L, -2);
    const char* value = lua_tostring(entry->L, -1);
    
    /* We don't allow setting the Content-Length header
     * from the script.
     */
    if (strcasecmp(key, "content-length") != 0) {
      headers = sdscatprintf(
        headers,
        "%s: %s\r\n",
        key, value
      );
    }

    /* Pop the value, keep the key for next. */
    lua_pop(entry->L, 1);
  }
  
  /* Pop the headers table. */
  lua_pop(entry->L, 1);
  

  sds response = sdscatprintf(
    sdsempty(),
    "HTTP/1.1 %d %s\r\n"
    "Content-Length: %zu\r\n"
    "%s"
    "\r\n",
    status,
    webserver_reason(status),
    body_size,
    headers
  );

  sdsfree(headers);

  response = sdscatlen(response, body, body_size);

  /* Add the response to the memory pool for this connection.
   * This will make sure it automatically gets freed once
   * the connection terminates.
   */
  pool_add(&web->pool, response, (pool_free_cb)sdsfree);

  webserver_respond(web, response, sdslen(response), 0);

  /* Return the stack to the starting state. */
  lua_pop(entry->L, lua_gettop(entry->L) - 2);
}


static void on_webserver_handle_http(webclient_t* web) {
  on_webserver_handle(web, 0);
}


static void on_webserver_handle_https(webclient_t* web) {
  on_webserver_handle(web, 1);
}


static void on_webserver_close(webclient_t* web) {
  (void)web;
}


static void on_webserver_error(const char* error) {
  puts(error);
}


static void on_print(uv_timer_t* handle, int status) {
  (void)handle;
  (void)status;

  static int printed = 40-1;

  if (++printed == 40) {
    printf("handled    http   https\n");
    printed = 0;
  }

  printf("%6u   %6u  %6u\n", handled, server_http.connected, server_https.connected);
  handled = 0;
}


int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("missing config file\n");
    exit(1);
  }

  JSON_Value*  config_value = json_parse_file(argv[1]);
  JSON_Object* config       = json_value_get_object(config_value);

  if (!config) {
    printf("could not load config file\n");
    exit(1);
  }
  
  
  int cachesize = json_object_get_number(config, "cachesize");

  if (cachesize <= 0) {
    cachesize = 64;
  }

  LRU_INIT(&scriptlru, cachesize);


#if !defined(_MSC_VER)
  /* Disable SIGPIPE. */
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigfillset(&sa.sa_mask);
  sigaction(SIGPIPE, &sa, 0);


  /* Try to increase our open file limit to it's max. */
  struct rlimit limit;

  if (getrlimit(RLIMIT_NOFILE, &limit) == -1) {
    perror("getrlimit");
    exit(1);
  }

  if (limit.rlim_max > limit.rlim_cur) {
    printf("increasing nofile to %lu\n", limit.rlim_cur);

    limit.rlim_cur = limit.rlim_max;

    if (setrlimit(RLIMIT_NOFILE, &limit) == -1) {
      perror("setrlimit");
      exit(1);
    }
  }
#endif  /* !defined(_MSC_VER) */


  loop = uv_default_loop();
  int err;


  UV_CHECK(uv_timer_init(loop, &print));
  UV_CHECK(uv_timer_start(&print, on_print, 6000, 6000));


  if (json_object_dotget_string(config, "http.ip")) {
    const char* http_ip   = json_object_dotget_string(config, "http.ip"  );
    int         http_port = json_object_dotget_number(config, "http.port");

    if (!http_ip || (http_port  <= 0)) {
      printf("invalid config\n");
      exit(1);
    }

    server_http.loop      = loop;
    server_http.handle_cb = on_webserver_handle_http;
    server_http.close_cb  = on_webserver_close;
    server_http.error_cb  = 0;
    
    if ((err = webserver_start(&server_http, http_ip, http_port)) != 0) {
      printf("%s\n", webserver_error(&server_http));
      exit(1);
    }
  } else {
    server_http.loop = 0;
  }


  if (json_object_dotget_string(config, "https.ip")) {
    const char* https_ip      = json_object_dotget_string(config, "https.ip"     );
    int         https_port    = json_object_dotget_number(config, "https.port"   );
    const char* https_pemfile = json_object_dotget_string(config, "https.pemfile");
    const char* https_ciphers = json_object_dotget_string(config, "https.ciphers");

    if (!https_ip      || (https_port <= 0) ||
        !https_pemfile || !https_ciphers
    ) {
      printf("invalid config\n");
      exit(1);
    }
    server_https.loop      = loop;
    server_https.handle_cb = on_webserver_handle_https;
    server_https.close_cb  = on_webserver_close;
    server_https.error_cb  = on_webserver_error;

    if ((err = webserver_start_ssl(&server_https, https_ip, https_port, https_pemfile, https_ciphers)) != 0) {
      printf("%s\n", webserver_error(&server_https));
      exit(1);
    }
  } else {
    server_https.loop = 0;
  }


  uv_run(loop, UV_RUN_DEFAULT);


  /* Clean up the lru cache. */
  lru_entry_t* p;
  while ((p = LRU_HEAD(&scriptlru))) {
    LRU_REMOVE(lru_entry_s, &scriptlru, p);
  }


  json_value_free(config_value);


  return 0;
}

