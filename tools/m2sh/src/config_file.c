/**
 *
 * Copyright (c) 2010, Zed A. Shaw and Mongrel2 Project Contributors.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 *     * Neither the name of the Mongrel2 Project, Zed A. Shaw, nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config/db.h>
#include <config/module.h>
#include <config/config.h>
#include "mimetypes.h"
#include <bstring.h>
#include "config_file.h"
#include "ast.h"
#include <dbg.h>
#include <stdlib.h>
#include "tnetstrings_impl.h"


#define CONFIRM_TYPE(N) check(Value_is(val, CLASS), "Not a class.");\
    check(biseqcstr(Class_ident(val->as.cls), N), "Should be a " # N ".");

int SERVER_ID = 0;
int HOST_ID = 0;

static inline tns_value_t *load_tns_from_ast(tst_t *settings, tst_t *fr, const char *name, ValueType type) {
    Value *data;
    struct tagbstring bname; 

    btfromcstr(bname, name);
    data = AST_get(settings, fr, &bname,  type);
    if (data)
        return AST_tns_convert_value(settings,data);
    return NULL;
}

static inline tns_value_t *dbify(tns_value_t *data) {
    tns_value_t *db = tns_new_list();
    tns_add_to_list(db,data);
    return db;
}


struct tagbstring CACHE_TTL = bsStatic("cache_ttl");

int Dir_load(tst_t *settings, tst_t *params)
{
    tns_value_t *base = load_tns_from_ast(settings, params, "base", VAL_QSTRING);
    tns_value_t *data = NULL;
    tns_value_t *cache_ttl;

    check(bchar(base->value.string, 0) != '/', 
        "Don't start the base with / in %s; it will fail when not in chroot.", base);
    check(bchar(base->value.string, blength(base->value.string) - 1) == '/', 
        "End directory base with / in %s or it won't work right.'", base);

    if(tst_search(params, bdata(&CACHE_TTL), blength(&CACHE_TTL))) {
        cache_ttl = load_tns_from_ast(settings, params, "cache_ttl", VAL_NUMBER);
    } else {
        cache_ttl = tns_new_integer(0);
    }

    data = tns_new_list();
    tns_add_to_list(data, base);
    tns_add_to_list(data, load_tns_from_ast(settings, params, "index_file", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, params, "default_ctype", VAL_QSTRING));
    tns_add_to_list(data, cache_ttl);
    
    data = dbify(data);
    int id = CONFIG_MODULE.save_dir(data);
    check(id >= 0, "Invalid database, couldn't query for directory: %s", base);

    tns_value_destroy(data);
    return id;

error:
    if(data) tns_value_destroy(data);
    return -1;
}

struct tagbstring RAW_PAYLOAD = bsStatic("raw_payload");
struct tagbstring PROTOCOL = bsStatic("protocol");

int Handler_load(tst_t *settings, tst_t *params)
{
   
    tns_value_t *data = NULL;
    tns_value_t *send_spec = load_tns_from_ast(settings, params, "send_spec", VAL_QSTRING);
    tns_value_t *raw_payload = NULL; 
    tns_value_t *protocol = NULL;

    if(tst_search(params, bdata(&RAW_PAYLOAD), blength(&RAW_PAYLOAD))) {
        raw_payload = load_tns_from_ast(settings, params, "raw_payload", VAL_NUMBER);
        if (raw_payload->value.number != 0) {
            tns_value_destroy(raw_payload);
            raw_payload = tns_new_integer(1);
        }
    } else {
        raw_payload = tns_new_integer(0);
    }

    if(tst_search(params, bdata(&PROTOCOL), blength(&PROTOCOL))) {
        protocol = load_tns_from_ast(settings, params, "protocol", VAL_QSTRING);
        btolower(protocol->value.string);
    } else {
        protocol = tns_parse_string("json", sizeof("json")-1);
    }

    data = tns_new_list();
    tns_add_to_list(data, send_spec);
    tns_add_to_list(data, load_tns_from_ast(settings, params, "send_ident", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, params, "recv_spec", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, params, "recv_ident", VAL_QSTRING));
    tns_add_to_list(data, raw_payload);
    tns_add_to_list(data, protocol);
    
    data = dbify(data);
    int id = CONFIG_MODULE.save_handler(data);
    check(id >= 0, "Failed to load Handler: %s", bdata(send_spec->value.string));

    tns_value_destroy(data);
    return id;

error:

    if(data) tns_value_destroy(data);
    return -1;
}


int Proxy_load(tst_t *settings, tst_t *params)
{
    tns_value_t *addr = load_tns_from_ast(settings, params, "addr", VAL_QSTRING);
    tns_value_t *port = load_tns_from_ast(settings, params, "port", VAL_NUMBER);

    tns_value_t *data = tns_new_list();
    tns_add_to_list(data, addr);
    tns_add_to_list(data, port);

    data = dbify(data);
    int id = CONFIG_MODULE.save_proxy(data);
    check(id>=0, "Failed to load Proxy: %s:%d", bdata(addr->value.string), port->value.number);

    tns_value_destroy(data);
    return id;

error:
    if(data) tns_value_destroy(data);
    return -1;
}

int Mimetypes_import()
{
    tns_value_t *data = NULL;
    int i;
    for (i=0; i < N_MIMETYPES_DEFAULT; i+=2) {
        data = tns_new_list();
        tns_add_to_list(data, tns_parse_string(MIMETYPES_DEFAULT[i],  strlen(MIMETYPES_DEFAULT[i]))); 
        tns_add_to_list(data, tns_parse_string(MIMETYPES_DEFAULT[i+1],strlen(MIMETYPES_DEFAULT[i+1])));

        data = dbify(data);
        int id = CONFIG_MODULE.save_mimetype(data);
        check(id >= 0, "Failed to load initial mimetypes");
        tns_value_destroy(data);    
        data = NULL;
    }

    return 0;
error:
    if(data) tns_value_destroy(data);
    return -1;
}

int Mimetypes_load(tst_t *settings, Pair *pair)
{
    bstring ext = Pair_key(pair);
    tns_value_t *data = NULL;
    Value *val = Pair_value(pair);
    check(val, "Error loading Mimetype %s", bdata(Pair_key(pair)));

    data = tns_new_list();
    tns_list_addstr(data, ext);
    tns_list_addstr(data, val->as.string->data);

    data = dbify(data);
    int id=CONFIG_MODULE.save_mimetype(data);

    check(id >= 0, "Failed to add mimetype: %s=%s",
            bdata(ext), bdata(val->as.string->data));

    tns_value_destroy(data);
    return 0;

error:
    if(data) tns_value_destroy(data);
    return -1;
}

int Settings_load(tst_t *settings, Pair *pair)
{
    bstring name = Pair_key(pair);
    tns_value_t *data = NULL;
    Value *val = Pair_value(pair);
    check(val, "Error loading Setting %s", bdata(Pair_key(pair)));

    data = tns_new_list();
    tns_list_addstr( data, name );
    tns_list_addstr( data, val->as.string->data);

    data = dbify(data);
    int id = CONFIG_MODULE.save_setting(data);
    check(id >= 0, "Failed to add setting: %s=%s",
            bdata(name), bdata(val->as.string->data));

    tns_value_destroy(data);
    return 0;

error:
    if(data) tns_value_destroy(data);
    return -1;
}


int Route_load(tst_t *settings, Pair *pair)
{
    bstring name = Pair_key(pair);
    tns_value_t *data = NULL;
    Value *val = Pair_value(pair);
    bstring type = NULL;
    int rc = 0;

    check(val, "Error loading route: %s", bdata(name));
    check(Value_is(val, CLASS), "Expected a Class but got a %s instead.",
            Value_type_name(val->type));
    Class *cls = val->as.cls;
    type = bstrcpy(Class_ident(cls));
    btolower(type);

    if(cls->id == -1) {
        if(biseqcstr(type, "dir")) {
            rc = Dir_load(settings, cls->params);
        } else if(biseqcstr(type, "proxy")) {
            rc = Proxy_load(settings, cls->params);
        } else if(biseqcstr(type, "handler")) {
            rc = Handler_load(settings, cls->params);
        } else {
            sentinel("Invalid type of route target: %s", bdata(Class_ident(cls)));
        }

        check(rc != -1, "Failed to create target for route %s", bdata(name));
        cls->id = rc;
    }

    data = tns_new_list();

    tns_list_addstr(data, name);
    tns_add_to_list(data, tns_new_integer(HOST_ID));
    tns_add_to_list(data, tns_new_integer(cls->id));
    tns_list_addstr(data, type);

    data = dbify(data);
    int id = CONFIG_MODULE.save_route(data);
    check(id >=0, "Failed to intialize route.");

    tns_value_destroy(data);
    bdestroy(type);
    return 0;

error:
    if(data) tns_value_destroy(data);
    if(type) bdestroy(type);
    return -1;
}

struct tagbstring MATCHING_PARAM = bsStatic("matching");

int Plugin_load(tst_t *settings, Value *val, int (*config_func)(tns_value_t *), const char *type)
{
    Class *cls = val->as.cls;
    tns_value_t *data = NULL;
    struct tagbstring SETTINGS_VAR = bsStatic("settings");
    char *converted_settings = NULL;
    tns_value_t *filter_tns = NULL;

    CONFIRM_TYPE(type);

    const char *name = AST_str(settings, cls->params, "name", VAL_QSTRING);
    check(name != NULL, "You must set a name for the filter.");

    Value *filter_settings = AST_get(settings, cls->params, &SETTINGS_VAR, VAL_HASH);
    check(filter_settings != NULL, "Invalid or missing settings for Filter '%s'", name);

    filter_tns = AST_tns_convert_value(settings, filter_settings);
    check(filter_tns, "Failed to convert settings for filter '%s'", name);
    check(tns_get_type(filter_tns) == tns_tag_dict,
            "Settings for Filter '%s' must be a dict type.", name);

    size_t len = 0;
    converted_settings = tns_render(filter_tns, &len);
    tns_value_destroy(filter_tns);
    filter_tns = NULL;

    check(converted_settings != NULL && len > 0,
            "Failed to convert final Filter settings to tnetstring for Filter '%s'",
            name);

    data = tns_new_list();
    tns_add_to_list(data, tns_new_integer(SERVER_ID));
    tns_add_to_list(data, tns_parse_string(name, strlen(name)));
    tns_add_to_list(data, tns_parse_string(converted_settings, len));

    data = dbify(data);
    int id = config_func(data);
    check(id >= 0, "Failed to store Filter: '%s'", name);
    tns_value_destroy(data);
    data = NULL;

    free(converted_settings);

    return 0;
error:
    if(converted_settings) free(converted_settings);
    if(filter_tns) tns_value_destroy(filter_tns);
    if(data) tns_value_destroy(data);
    return -1;
}
int Filter_load_m2sh(tst_t *settings, Value *val)
{
    return Plugin_load(settings,val,CONFIG_MODULE.save_filter,"Filter");
}
int Xrequest_load_m2sh(tst_t *settings, Value *val)
{
    return Plugin_load(settings,val,CONFIG_MODULE.save_xrequest,"Xrequest");
}


int Host_load(tst_t *settings, Value *val)
{
    tns_value_t *data = NULL;

    CONFIRM_TYPE("Host");

    Class *cls = val->as.cls;
    struct tagbstring ROUTES_VAR = bsStatic("routes");

    const char *name = AST_str(settings, cls->params, "name", VAL_QSTRING);
    const char *matching = name; // default to this then change it
    check(name, "No name set for Host.");

    if(tst_search(cls->params, bdata(&MATCHING_PARAM), blength(&MATCHING_PARAM))) {
        // specified matching so use that
        matching = AST_str(settings, cls->params, bdata(&MATCHING_PARAM), VAL_QSTRING);
    }

    data = tns_new_list();

    tns_add_to_list(data, tns_parse_string(name, strlen(name)));
    tns_add_to_list(data, tns_parse_string(matching, strlen(name)));
    tns_add_to_list(data, tns_new_integer(SERVER_ID));

    data = dbify(data);
    int id = CONFIG_MODULE.save_host(data);
    check(id >= 0, "Failed to store host: %s", name);
    tns_value_destroy(data);
    data = NULL;
    
    cls->id = HOST_ID = id;

    Value *routes = AST_get(settings, cls->params, &ROUTES_VAR, VAL_HASH);
    check(routes, "Didn't find any routes for %s", name);

    AST_walk_hash(settings, routes, Route_load);

    return 0;

error:
    if(data) tns_value_destroy(data);
    return -1;
}

struct tagbstring BIND_ADDR = bsStatic("bind_addr");
struct tagbstring USE_SSL = bsStatic("use_ssl");

int Server_load(tst_t *settings, Value *val)
{
    tns_value_t *data = NULL;
    CONFIRM_TYPE("Server");
    Class *cls = val->as.cls;
    struct tagbstring HOSTS_VAR = bsStatic("hosts");
    struct tagbstring FILTERS_VAR = bsStatic("filters");
    struct tagbstring XREQUESTS_VAR = bsStatic("xrequests");
    tns_value_t *bind_addr = NULL;
    tns_value_t *use_ssl = NULL;

    if(tst_search(cls->params, bdata(&BIND_ADDR), blength(&BIND_ADDR))) {
        bind_addr = load_tns_from_ast(settings, cls->params, bdata(&BIND_ADDR), VAL_QSTRING);
    } else {
        bind_addr = tns_parse_string("0.0.0.0", sizeof("0.0.0.0")-1);
    }

    if(tst_search(cls->params, bdata(&USE_SSL), blength(&USE_SSL))) {
        use_ssl = load_tns_from_ast(settings, cls->params, bdata(&USE_SSL), VAL_NUMBER);
    } else {
        use_ssl = tns_new_integer(0);
    }

    
    data = tns_new_list();

    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "uuid", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "default_host", VAL_QSTRING));
    tns_add_to_list(data, bind_addr);
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "port", VAL_NUMBER));
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "chroot", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "access_log", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "error_log", VAL_QSTRING));
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "pid_file", VAL_QSTRING));
    tns_add_to_list(data, use_ssl);
    tns_add_to_list(data, load_tns_from_ast(settings, cls->params, "name", VAL_QSTRING));

    data = dbify(data);
    int id = CONFIG_MODULE.save_server(data);
    check(id >=0, "Failed to save server");

    cls->id = SERVER_ID = id;
    tns_value_destroy(data);
    data = NULL;

    // setup the hosts
    Value *hosts = AST_get(settings, cls->params, &HOSTS_VAR, VAL_LIST);
    check(hosts != NULL, "Could not find Server.hosts setting in host %s:%s",
            AST_str(settings, cls->params, "uuid", VAL_QSTRING),
            AST_str(settings, cls->params, "name", VAL_QSTRING));

    AST_walk_list(settings, hosts->as.list, Host_load);

    // setup the filters
    Value *filters = AST_get(settings, cls->params, &FILTERS_VAR, VAL_LIST);

    if(filters != NULL) {
        AST_walk_list(settings, filters->as.list, Filter_load_m2sh);
    }

    Value *xrequests = AST_get(settings, cls->params, &XREQUESTS_VAR, VAL_LIST);

    if(xrequests != NULL) {
        AST_walk_list(settings, xrequests->as.list, Xrequest_load_m2sh);
    }

    return 0;

error:
    if(data) tns_value_destroy(data);
    return -1;
}

static inline int Config_setup(const char *db_file)
{
    int rc = CONFIG_MODULE.init(db_file);
    check(rc == 0, "Failed to load configuration URL: %s.", db_file);

    if (CONFIG_MODULE.supports_transactions) {
        //tns_value_t *res = DB_exec("begin");
        //check(res != NULL, "Couldn't start transaction.");
        rc = CONFIG_MODULE.begin();
        check(rc == 0, "Couldn't start transaction.");
    } else {
        log_warn("Transactions not supported");
    }        


    //rc = sqlite3_exec(CONFIG_DB, bdata(&CONFIG_SCHEMA), NULL, NULL, &zErrMsg);
    //check(rc == SQLITE_OK, "Failed to load initial schema: %s", zErrMsg);
    rc = CONFIG_MODULE.remake_schema();
    check(rc == 0, "Failed to load initial schema.");

    //tns_value_destroy(res);
    return 0;

error:
    //if(res) tns_value_destroy(res);
    //if(zErrMsg) sqlite3_free(zErrMsg);
    return -1;
}


static inline int Config_commit()
{
    //return DB_exec("commit") == NULL ? -1 : 0;
    if (CONFIG_MODULE.supports_transactions) {
        return CONFIG_MODULE.commit();
    }
    return 0;
}


int Config_load(const char *config_file, const char *config_module, const char *db_file)
{
    int rc = 0;
    tst_t *settings = NULL;
    struct tagbstring SETTINGS_VAR = bsStatic("settings");
    struct tagbstring MIMETYPES_VAR = bsStatic("mimetypes");

    settings = Parse_config_file(config_file);
    check(settings != NULL, "Error parsing config file: %s.", config_file);

    if (config_module != NULL && strlen(config_module) > 0) {
        rc = Config_module_load(config_module);
        check(rc == 0, "Error loading config module: %s.", config_module);

        if (!CONFIG_MODULE.supports_save)
           sentinel("Config module does not support saving: %s.", config_module);
    }

    rc = Config_setup(db_file);
    check(rc == 0, "Failed to configure config db: %s", db_file);

    rc = AST_walk(settings, Server_load);
    check(rc == 0, "Failed to process the config file: %s", config_file);

    Value *set = AST_get(settings, settings, &SETTINGS_VAR, VAL_HASH);

    if(set) {
        rc = AST_walk_hash(settings, set, Settings_load);
        check(rc == 0, "Failed to load the settings. Aborting.");
    }

    rc = Mimetypes_import();
    check(rc == 0, "Failed to import default mimetypes.");

    Value *mime = AST_get(settings, settings, &MIMETYPES_VAR, VAL_HASH);
    if(mime) {
        AST_walk_hash(settings, mime, Mimetypes_load);
        check(rc == 0, "Failed to load the mimetypes. Aborting.");
    }

    rc = Config_commit();
    check(rc == 0, "Failed to commit config db: %s", db_file);

    AST_destroy(settings);
    DB_close();
    return 0;
error:
    AST_destroy(settings);
    DB_close();
    return -1;
}



