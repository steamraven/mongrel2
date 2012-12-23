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

#include "config/module.h"
#include "config/db.h"

int default_init(const char *path)
{
    return DB_init(path);
}

void default_close()
{
    DB_close();
}

tns_value_t *default_load_handler(int handler_id)
{
    const char *HANDLER_QUERY = "SELECT id, send_spec, send_ident, recv_spec, recv_ident, raw_payload, protocol FROM handler WHERE id=%d";
    return DB_exec(HANDLER_QUERY, handler_id);
}

tns_value_t *default_load_proxy(int proxy_id)
{
    const char *PROXY_QUERY = "SELECT id, addr, port FROM proxy WHERE id=%d";
    return DB_exec(PROXY_QUERY, proxy_id);
}

tns_value_t *default_load_dir(int dir_id)
{
    const char *DIR_QUERY = "SELECT id, base, index_file, default_ctype, cache_ttl FROM directory WHERE id=%d";
    return DB_exec(DIR_QUERY, dir_id);
}

tns_value_t *default_load_routes(int host_id, int server_id)
{
    const char *ROUTE_QUERY = "SELECT route.id, route.path, route.host_id, route.target_id, route.target_type "
        "FROM route, host WHERE host_id=%d AND "
        "host.server_id=%d AND host.id = route.host_id";

    return DB_exec(ROUTE_QUERY, host_id, server_id);
}

tns_value_t *default_load_hosts(int server_id)
{
    const char *HOST_QUERY = "SELECT id, name, matching, server_id FROM host WHERE server_id = %d";
    return DB_exec(HOST_QUERY, server_id);
}

tns_value_t *default_load_server(const char *uuid)
{

    if (uuid == NULL || strlen(uuid) == 0){
        const char *SERVER_QUERY  = "SELECT id, uuid, default_host, bind_addr, port, chroot, access_log, error_log, pid_file, use_ssl, name FROM server";
        return DB_exec(SERVER_QUERY);
    } else {
        const char *SERVER_QUERY  = "SELECT id, uuid, default_host, bind_addr, port, chroot, access_log, error_log, pid_file, use_ssl, name FROM server WHERE uuid=%Q";
        return DB_exec(SERVER_QUERY, uuid);
    }
}


tns_value_t *default_load_mimetypes()
{
    const char *MIME_QUERY = "SELECT id, extension, mimetype FROM mimetype";
    return DB_exec(MIME_QUERY);
}

tns_value_t *default_load_settings()
{
    const char *SETTINGS_QUERY = "SELECT id, key, value FROM setting";
    return DB_exec(SETTINGS_QUERY);
}
     
tns_value_t *default_load_filters(int server_id)
{
    const char *FILTER_QUERY = "SELECT id, name, settings FROM filter WHERE server_id = %d";
    return DB_exec(FILTER_QUERY, server_id);
}
     
tns_value_t *default_load_xrequests(int server_id)
{
    const char *FILTER_QUERY = "SELECT id, name, settings FROM xrequest WHERE server_id = %d";
    return DB_exec(FILTER_QUERY, server_id);
}

int default_begin() {
    if (DB_exec("BEGIN") != NULL)
        return 0;
    return 1;
}

int default_commit() {
    if (DB_exec("COMMIT") != NULL)
        return 0;
    return 1;
}
struct tagbstring CONFIG_SCHEMA;
int default_remake_schema() {
  return DB_exec2(bdata(&CONFIG_SCHEMA));
}

int default_save_handler(tns_value_t * data){
    const char *QUERY = "INSERT INTO handler (send_spec, send_ident, recv_spec, recv_ident, raw_payload, protocol) VALUES (%Q, %Q, %Q, %Q, %d, %Q);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 6,
            tns_tag_string, tns_tag_string, tns_tag_string,
            tns_tag_string, tns_tag_number, tns_tag_string);
    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), //send_spec
                bdata(DB_get_as(data, 0, 1, string)), //send_ident
                bdata(DB_get_as(data, 0, 2, string)), //recv_spec
                bdata(DB_get_as(data, 0, 3, string)), //recv_ident
                      DB_get_as(data, 0, 4, number) , //raw_payload
                bdata(DB_get_as(data, 0, 5, string))  //protocol
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;

}

int default_save_proxy(tns_value_t * data) {
    const char *QUERY = "INSERT INTO proxy (addr, port) VALUES (%Q, %Q);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 2,
            tns_tag_string, tns_tag_number);
    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), //addr
                      DB_get_as(data, 0, 1, number)  //port
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;

}

int default_save_dir(tns_value_t * data) {
    const char *QUERY = "INSERT INTO directory (base, index_file, default_ctype, cache_ttl) VALUES (%Q, %Q, %Q, %d);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 4,
            tns_tag_string, tns_tag_string,
            tns_tag_string, tns_tag_number);

    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), //base
                bdata(DB_get_as(data, 0, 1, string)), //index_file
                bdata(DB_get_as(data, 0, 2, string)), //default_ctype
                      DB_get_as(data, 0, 3, number)   //cache_ttl
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;
}

int default_save_route(tns_value_t * data) {
    const char *QUERY = "INSERT INTO route (path, host_id, target_id, target_type) VALUES (%Q, %d, %d, %Q);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 4,
            tns_tag_string, tns_tag_number, tns_tag_number, tns_tag_string);

    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), //path
                      DB_get_as(data, 0, 1, number) , //host_id
                      DB_get_as(data, 0, 2, number) , //target_id
                bdata(DB_get_as(data, 0, 3, string))  //target_typoe
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;
}

int default_save_host(tns_value_t * data) {
    const char *QUERY = "INSERT INTO host (name, matching, server_id ) VALUES (%Q, %Q, %d);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 3,
            tns_tag_string, tns_tag_string, tns_tag_number);

    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), //name
                bdata(DB_get_as(data, 0, 1, string)), //matching
                      DB_get_as(data, 0, 2, number)   //server_id

            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;
}

int default_save_server(tns_value_t * data) {
    const char *QUERY = "INSERT INTO server (uuid, default_host, bind_addr, port,  chroot, access_log, error_log, "
                        "pid_file, use_ssl, name) VALUES (%Q, %Q, %Q, %d, %Q, %Q, %Q, %Q, %d, %Q);";
    tns_value_t *res = NULL;

    DB_check(data, 0, 10,
            tns_tag_string, tns_tag_string, tns_tag_string, tns_tag_number,
            tns_tag_string, tns_tag_string, tns_tag_string, tns_tag_string, tns_tag_number, tns_tag_string);

    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), // uuid
                bdata(DB_get_as(data, 0, 1, string)), // default_host
                bdata(DB_get_as(data, 0, 2, string)), // bind_addr
                      DB_get_as(data, 0, 3, number) , // port
                bdata(DB_get_as(data, 0, 4, string)), // chroot
                bdata(DB_get_as(data, 0, 5, string)), // access_log
                bdata(DB_get_as(data, 0, 6, string)), // error_log
                bdata(DB_get_as(data, 0, 7, string)), // pid_file
                      DB_get_as(data, 0, 8, number) , // use_ssl
                bdata(DB_get_as(data, 0, 9, string))  // name

            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;
}

int save_plugin(const char *QUERY, tns_value_t *data) {
    tns_value_t *res = NULL;

    DB_check(data, 0, 3,
            tns_tag_number, tns_tag_string, tns_tag_string);

    res = DB_exec(QUERY, 
                      DB_get_as(data, 0, 0, number) , // SERVER_ID
                bdata(DB_get_as(data, 0, 1, string)), // key
                bdata(DB_get_as(data, 0, 2, string))  // value
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;

}

int save_pair(const char *QUERY, tns_value_t *data) {
    tns_value_t *res = NULL;

    DB_check(data, 0, 2,
            tns_tag_string, tns_tag_string);

    res = DB_exec(QUERY, 
                bdata(DB_get_as(data, 0, 0, string)), // key
                bdata(DB_get_as(data, 0, 1, string))  // value
            );
    check(res != NULL, "Failed to execute sql %s", QUERY);
    tns_value_destroy(res); 
    return DB_lastid();

error:
    tns_value_destroy(res);
    return -1;

}


int default_save_mimetype(tns_value_t * data) {
    const char *QUERY = "INSERT INTO mimetype (extension, mimetype) VALUES (%Q, %Q);";
    return save_pair(QUERY, data);
}

int default_save_setting(tns_value_t * data) {
    const char *QUERY = "INSERT INTO setting (key, value) VALUES (%Q, %Q);";
    return save_pair(QUERY, data);
}

int default_save_filter(tns_value_t * data) {
    const char *QUERY = "INSERT INTO filter (server_id, name, settings) VALUES (%d, %Q, %Q);";
    return save_plugin(QUERY, data);
}

int default_save_xrequest(tns_value_t * data) {
    const char *QUERY = "INSERT INTO xrequest (server_id, name, settings) VALUES (%d, %Q, %Q);";
    return save_plugin(QUERY, data);
}

ConfigModule CONFIG_MODULE = {
    .init = default_init,
    .close = default_close,
    .load_handler = default_load_handler,
    .load_proxy = default_load_proxy,
    .load_dir = default_load_dir,
    .load_routes = default_load_routes,
    .load_hosts = default_load_hosts,
    .load_server = default_load_server,
    .load_mimetypes = default_load_mimetypes,
    .load_settings = default_load_settings,
    .load_filters = default_load_filters,
    .load_xrequests = default_load_xrequests,
    .supports_transactions = 1,    
    .begin = default_begin,
    .commit = default_commit,
    .supports_save = 1,
    .remake_schema = default_remake_schema,
    .save_handler = default_save_handler,
    .save_proxy = default_save_proxy,
    .save_dir = default_save_dir,
    .save_route = default_save_route,
    .save_host = default_save_host,
    .save_server = default_save_server,
    .save_mimetype = default_save_mimetype,
    .save_setting = default_save_setting,
    .save_filter = default_save_filter,
    .save_xrequest = default_save_xrequest
};

struct tagbstring CONFIG_SCHEMA = bsStatic(
"DROP TABLE IF EXISTS server;\n"
"DROP TABLE IF EXISTS host;\n"
"DROP TABLE IF EXISTS handler;\n"
"DROP TABLE IF EXISTS proxy;\n"
"DROP TABLE IF EXISTS route;\n"
"DROP TABLE IF EXISTS statistic;\n"
"DROP TABLE IF EXISTS mimetype;\n"
"DROP TABLE IF EXISTS setting;\n"
"DROP TABLE IF EXISTS directory;\n"
"DROP TABLE IF EXISTS filter;\n"
"DROP TABLE IF EXISTS xrequest;\n"
"\n"
"CREATE TABLE server (id INTEGER PRIMARY KEY,\n"
"    uuid TEXT,\n"
"    access_log TEXT,\n"
"    error_log TEXT,\n"
"    chroot TEXT DEFAULT '/var/www',\n"
"    pid_file TEXT,\n"
"    default_host TEXT,\n"
"    name TEXT DEFAULT '',\n"
"    bind_addr TEXT DEFAULT \"0.0.0.0\",\n"
"    port INTEGER,\n"
"    use_ssl INTEGER default 0);\n"
"\n"
"CREATE TABLE host (id INTEGER PRIMARY KEY, \n"
"    server_id INTEGER,\n"
"    maintenance BOOLEAN DEFAULT 0,\n"
"    name TEXT,\n"
"    matching TEXT);\n"
"\n"
"CREATE TABLE handler (id INTEGER PRIMARY KEY,\n"
"    send_spec TEXT, \n"
"    send_ident TEXT,\n"
"    recv_spec TEXT,\n"
"    recv_ident TEXT,\n"
"   raw_payload INTEGER DEFAULT 0,\n"
"   protocol TEXT DEFAULT 'json');\n"
"\n"
"CREATE TABLE proxy (id INTEGER PRIMARY KEY,\n"
"    addr TEXT,\n"
"    port INTEGER);\n"
"\n"
"CREATE TABLE directory (id INTEGER PRIMARY KEY,"
"   base TEXT,"
"   index_file TEXT,"
"   default_ctype TEXT,"
"   cache_ttl INTEGER DEFAULT 0);"
"\n"
"CREATE TABLE route (id INTEGER PRIMARY KEY,\n"
"    path TEXT,\n"
"    reversed BOOLEAN DEFAULT 0,\n"
"    host_id INTEGER,\n"
"    target_id INTEGER,\n"
"    target_type TEXT);\n"
"\n"
"CREATE TABLE setting (id INTEGER PRIMARY KEY, key TEXT, value TEXT);\n"
"\n"
"CREATE TABLE statistic (id SERIAL, \n"
"    other_type TEXT,\n"
"    other_id INTEGER,\n"
"    name TEXT,\n"
"    sum REAL,\n"
"    sumsq REAL,\n"
"    n INTEGER,\n"
"    min REAL,\n"
"    max REAL,\n"
"    mean REAL,\n"
"    sd REAL,\n"
"    primary key (other_type, other_id, name));\n"
"\n"
"CREATE TABLE mimetype (id INTEGER PRIMARY KEY, mimetype TEXT, extension TEXT);\n"
"\n"
"CREATE TABLE filter (id INTEGER PRIMARY KEY, \n"
"    server_id INTEGER, \n"
"    name TEXT, \n"
"    settings TEXT);\n"
"\n"
"CREATE TABLE xrequest (id INTEGER PRIMARY KEY, \n"
"    server_id INTEGER, \n"
"    name TEXT, \n"
"    settings TEXT);\n"
"\n"
"CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY,\n"
"    who TEXT,\n"
"    what TEXT,\n"
"    location TEXT,\n"
"    happened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
"    how TEXT,\n"
"    why TEXT);");


