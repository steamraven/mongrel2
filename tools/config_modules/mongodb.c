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

#include <dbg.h>
#include <config/module.h>
#include "tnetstrings_impl.h"

#include "mongo.h"

static mongo connexion[1];
static bstring dbname;

#define MONGODB_HOST_PORT_SEPARATOR ':'
#define MONGODB_LOGIN_SEPARATOR '@'
#define MONGODB_USER_PASS_SEPARATOR ':'
#define MONGODB_DB_SEPARATOR '?'
#define MONGODB_OPTION_SEPARATOR '&'
#define MONGODB_IP_SEPARATOR        ','
#define MONGODB_TOKEN_SEPARATOR     '/'
#define MONGODB_TOKEN_URL_SCHEME    "mongodb:"

static int bpartition(bstring str, const char sep, bstring *first, bstring *rest) {
    int i = bstrchr(str,sep);
    if (i == BSTR_ERR) {
        if (first)
            *first = bstrcpy(str);
        if (rest)
            *rest = NULL;
        return 0;
    }
    if (first)
        *first = bmidstr(str,0, i);
    if (rest)
        *rest = bmidstr(str, i+1, blength(str));
    return 0;
}
static int brpartition(bstring str, const char sep, bstring *rest, bstring *last) {
    int i = bstrrchr(str,sep);
    if (i == BSTR_ERR) {
        if (last)        
            *last = bstrcpy(str);
        if (rest)
            *rest = NULL;
        return 0;
    }
    if (rest)
        *rest = bmidstr(str,0, i);
    if (last)    
        *last = bmidstr(str, i+1, blength(str));
    return 0;
}

static int config_init_index(void)
{
    bson key[1];
    log_info ("Ensure that the database have index");

    bson_init(key);
    bson_append_int(key, "id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.handler", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.proxy", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.directory", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "host_id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.route", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "server_id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.host", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "uuid", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.server", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    bson_init(key);
    bson_append_int(key, "server_id", 1);
    bson_finish(key);
    mongo_create_index(connexion, "mongrel2.filter", key, MONGO_INDEX_BACKGROUND, NULL);
    bson_destroy(key);

    return 0;
}

static int config_init_server(bstring ip, bstring options)
{
    int ret = -1;
    int status, port = MONGO_DEFAULT_PORT;
    bstring host = NULL, sport = NULL;

    status = bpartition(ip, MONGODB_HOST_PORT_SEPARATOR, &host, &sport);
    check (status == 0, "Error on bsplit"); 

    if (sport != NULL)
        port = atoi(bdata(sport));

    log_info ("Connecting to server %s:%d", bdata(host),port);
    status = mongo_connect(connexion, bdata(host), port);
    check(status == MONGO_OK, "Connection fail to mongoDB configuration server.");

    ret = 0;

error:
    bdestroy(host);
    bdestroy(sport);
    return ret;
}

static int config_init_replicaset(bstring ip_string, bstring options)
{
    int ret = -1;
    int i, status, port;
    bstring replicaset = NULL;
    bstring host = NULL, sport = NULL;;
    struct bstrList *ips = NULL;
    const char option_name[] = "replicaset=";

    //find replica set name:
    i = binstrcaseless(options, 0, bfromcstr(option_name));
    check(i!= BSTR_ERR, "Must provide relicaset option");
    status = bassignmidstr(options, options, i+sizeof(option_name), blength(options));
    check(status ==0, "Error getting replicaset");
    status = bpartition(options, MONGODB_OPTION_SEPARATOR, &replicaset, NULL);
    check (status == 0, "Error getting replicaset");

    mongo_replset_init(connexion, bdata(replicaset));
    log_info("Connecting to replicaset \"%s\"", bdata(replicaset));

    // parse ips
    ips = bsplit(ip_string, MONGODB_IP_SEPARATOR);

    i = ips->qty;
    while(--i >= 0) {
        //TODO?: use bpartition
        port = MONGO_DEFAULT_PORT;
        status = bpartition(ips->entry[i], MONGODB_HOST_PORT_SEPARATOR, &host, &sport);
        check (status == 0, "Error on bsplit"); 

        if (sport != NULL)
            port = atoi(bdata(sport));

        mongo_replset_add_seed(connexion,bdata(host), port);
        log_info("Add seed %s:%d", bdata( host), port);
        bdestroy(host), host = NULL;
        bdestroy(sport), sport = NULL;
    }

    status = mongo_replset_connect(connexion);
    check(status == MONGO_OK, "Connection fail to mongoDB configuration replicaset.");

    ret = 0;

error:
    bstrListDestroy(ips);
    bdestroy(replicaset);
    bdestroy(host);
    bdestroy(sport);
    return ret;
}

/*
 *  Init the config system from a path string.
 *  Some example of mongodb description to server or replica set:
 
        mongodb://localhost/mongrel2_collection
        mongodb://localhost:27017/mongrel2
        mongodb://user:pass@localhost:27017/mongrel2

        mongodb://srv1:27017,srv2:27018/mongrel2?relicaSet=test
        mongodb://srv1,srv2,srv3,srv4/m2?replicaSet=web
        mongodb://user:pass@srv1,srv2/m2?replicaSet=web
 */


int config_init(const char *path)
{
    int status, ret = -1;
    struct bstrList *tokens = NULL;
    struct bstrList *work = NULL;
    bstring dbspec = NULL;
    bstring login = NULL;
    bstring user = NULL;
    bstring pass = NULL;
    bstring ips = NULL;
    bstring options = NULL;

    log_info("Init mongoDB configuration module");

    dbspec = bfromcstr(path);
    check(dbspec != NULL, "Can't read path.");

    tokens = bsplit(dbspec, MONGODB_TOKEN_SEPARATOR);
    check(tokens != NULL, "Can't split the path.");
    check(tokens->qty == 3 || tokens->qty == 4,"Invalid database specification format.");

    check(biseqcstr(tokens->entry[0], MONGODB_TOKEN_URL_SCHEME) == 1, "Invalid url scheme");
    check(blength(tokens->entry[1]) == 0, "Invalid url format");

    // check for login info
    check(brpartition(tokens->entry[2], MONGODB_LOGIN_SEPARATOR, &login, &ips) == 0, "Can't extract login");

    // find user/pass
    if (login) {
        check(bpartition(login, MONGODB_USER_PASS_SEPARATOR, &user,&pass) == 0, "Can't extract user/pass");
    }

    //find dbname/options
    if (tokens->qty == 3) {
        // no dbname or options
        dbname = blk2bstr (bsStaticBlkParms ("admin"));
        
    } else {
        //dbname
        check(bpartition(tokens->entry[3], MONGODB_DB_SEPARATOR, &dbname, &options) == 0, "Can't extract dbname");
        if (blength(dbname) == 0) {
            bassignblk(dbname, bsStaticBlkParms("admin"));
        }
    }

    if (bstrchr(ips, MONGODB_IP_SEPARATOR) != BSTR_ERR) {
        ret = config_init_replicaset(ips, options);
    } else {
        ret = config_init_server(ips, options);
    }
    check(ret == 0, "Error during connection.");

    if (login) {
        log_info("Logging into database %s with user %s", bdata(dbname), bdata(user));
        status  = mongo_cmd_authenticate( connexion, bdata(dbname), bdata(user), bdata(pass));
        if (status != MONGO_OK) {
            mongo_destroy(connexion);
            ret = -1;
            sentinal("Error authenticating: %d", status);
        }
    }

    status = bconchar(dbname, '.');
    check (status != BSTR_ERR, "Error on bconchar");

    //ret = config_init_index();    
    //check(ret == 0, "Error during setup index.");

error:
    bdestroy(dbspec);
    bdestroy(login);
    bdestroy(user);
    bdestroy(pass);
    bdestroy(ips);
    bdestroy(options);

    bstrListDestroy(tokens);
    return ret;
}

/*
 *  Close the connection with the configuration server
 */
void config_close()
{
    log_info("Close mongoDB configuration module");
    mongo_destroy(connexion);
    bdestroy(dbname);
}

tns_value_t *mongo_cursor_to_tns_value(mongo_cursor *cursor, bson *fields)
{
    tns_value_t *ret = NULL;

    ret = tns_new_list();
    
    while (mongo_cursor_next(cursor) == MONGO_OK) {
        bson_iterator fields_iterator[1];
        
        tns_value_t *row = tns_new_list();
        bson_iterator_init(fields_iterator, fields);
        
        // For each fields in the query
        do {
            bson_iterator cursor_iterator[1];
            bson_type type;
            const char *string_data;
            int int_data;
            int bool_data;
            tns_value_t *el = NULL;
            
            type = bson_iterator_next(fields_iterator);
            if (type == BSON_EOO) { // EOO: End of object
                break;
            }
            
            type = bson_find(cursor_iterator, mongo_cursor_bson(cursor), bson_iterator_key(fields_iterator));
            switch (type) {
                case BSON_STRING:
                    string_data = bson_iterator_string(cursor_iterator);
                    el = tns_parse_string(string_data, strlen(string_data));
                    break;
                    
                case BSON_BOOL:
                    bool_data = bson_iterator_bool(cursor_iterator);
                    el = (bool_data) ? tns_get_true() : tns_get_false();
                    break;
                    
                case BSON_INT:
                    int_data = bson_iterator_int(cursor_iterator);
                    el = tns_new_integer(int_data);
                    break;

                default:
                    log_err("Not supported BSON type (%d)", type);
            }
            
            if (el) {
                tns_add_to_list(row, el);
                el = NULL;
            } else {
                // Go to next row
                break;
            }
        } while (1);
        
        tns_add_to_list(ret, row);
    }
    
    return ret;
}

tns_value_t *fetch_data(bstring collection_name, bson *fields, bson *query)
{
    int status;
    tns_value_t *ret = NULL;
    char *mongo_collection_name = NULL;
    mongo_cursor cursor[1];

    errno = 0;

    bstring collection = bstrcpy(dbname);
    check_mem(collection);

    status = bconcat(collection, collection_name);
    check(status == BSTR_OK, "Error on bconcat");

    mongo_collection_name = bstr2cstr(collection, '\0');
    check_mem(mongo_collection_name);
    
    mongo_cursor_init(cursor, connexion, mongo_collection_name);
    mongo_cursor_set_query(cursor, query);
    mongo_cursor_set_fields(cursor, fields);

    ret = mongo_cursor_to_tns_value(cursor, fields);

error:
    bdestroy(collection);
    bcstrfree(mongo_collection_name);
    mongo_cursor_destroy(cursor);
    return ret;
}
tns_value_t *config_load_handler(int handler_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading handler");

    bson_init(query);
    bson_append_int(query, "id", handler_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "send_spec", 1);
    bson_append_int(fields, "send_ident", 1);
    bson_append_int(fields, "recv_spec", 1);
    bson_append_int(fields, "recv_ident", 1);
    bson_append_int(fields, "raw_payload", 1);
    bson_append_int(fields, "protocol", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("handler");
    check_mem(collection);

    res = fetch_data(collection, fields, query);

error: 
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_proxy(int proxy_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading proxy");

    bson_init(query);
    bson_append_int(query, "id", proxy_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "addr", 1);
    bson_append_int(fields, "port", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("proxy");
    check_mem(collection);
    
    res = fetch_data(collection, fields, query);

error:   
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_dir(int dir_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading directory");

    bson_init(query);
    bson_append_int(query, "id", dir_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "base", 1);
    bson_append_int(fields, "index_file", 1);
    bson_append_int(fields, "default_ctype", 1);
    bson_append_int(fields, "cache_ttl", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("directory");
    check_mem(collection);
   
    res = fetch_data(collection, fields, query);

error:    
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_routes(int host_id, int server_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    // server_id is useless
    (void)server_id;

    debug("Loading route");

    bson_init(query);
    bson_append_int(query, "host_id", host_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "path", 1);
    bson_append_int(fields, "host_id", 1);
    bson_append_int(fields, "target_id", 1);
    bson_append_int(fields, "target_type", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("route");
    check_mem(collection);
    
    res = fetch_data(collection, fields, query);

error:    
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_hosts(int server_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading host");

    bson_init(query);
    bson_append_int(query, "server_id", server_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "name", 1);
    bson_append_int(fields, "matching", 1);
    bson_append_int(fields, "server_id", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("host");
    check_mem(collection);
    
    res = fetch_data(collection, fields, query);

error:    
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_server(const char *uuid)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading server");

    bson_init(query);
    if (uuid && strlen(uuid) > 0)
        bson_append_string(query, "uuid", uuid);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "uuid", 1);
    bson_append_int(fields, "default_host", 1);
    bson_append_int(fields, "bind_addr", 1);
    bson_append_int(fields, "port", 1);
    bson_append_int(fields, "chroot", 1);
    bson_append_int(fields, "access_log", 1);
    bson_append_int(fields, "error_log", 1);
    bson_append_int(fields, "pid_file", 1);
    bson_append_int(fields, "use_ssl", 1);
    bson_append_int(fields, "name", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("server");
    check_mem(collection);

    res = fetch_data(collection, fields, query);

error:    
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_mimetypes()
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading mimetypes");

    bson_init(query);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "extension", 1);
    bson_append_int(fields, "mimetype", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("mimetype");
    check_mem(collection);

    res = fetch_data(collection, fields, query);

error:
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_settings()
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading setting");

    bson_init(query);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "key", 1);
    bson_append_int(fields, "value", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("setting");
    check_mem(collection);

    res = fetch_data(collection, fields, query);

error:
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

tns_value_t *config_load_filters(int server_id)
{
    tns_value_t *res = NULL;
    bson query[1], fields[1];

    debug("Loading filter");

    bson_init(query);
    bson_append_int(query, "server_id", server_id);
    bson_finish(query);
    
    bson_init(fields);
    bson_append_int(fields, "id", 1);
    bson_append_int(fields, "filter", 1);
    bson_append_int(fields, "settings", 1);
    bson_finish(fields);

    bstring collection = bfromcstr("filter");
    check_mem(collection);

    res = fetch_data(collection, fields, query);

error:
    bdestroy(collection);
    bson_destroy(fields);
    bson_destroy(query);
    
    return res;
}

