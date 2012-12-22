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

#include <unistd.h>
#include <sqlite3.h>
#include <dbg.h>
#include <tnetstrings.h>
#include "../commands.h"
#include "../query_print.h"
#include "running.h"
#include <config/db.h>
#include <config/module.h>
#include <config/config.h>
#include <tnetstrings.h>

int open_config(Command *cmd)
{
    bstring db_file = option(cmd, "db",NULL);
    bstring conf_url = option(cmd, "url", NULL);
    bstring conf_style = option(cmd, "style", NULL);

    if(conf_url == NULL && db_file == NULL) {
        db_file = bfromcstr("config.sqlite");
    }
    check(db_file != NULL || (conf_url != NULL && conf_style != NULL),
            "You must give either --db or --style and --url.");

    if (db_file) {
        check(Config_init_db(bdata(db_file)) ==0, "Error opening database: %s", bdata(db_file));
    } else {
        check(Config_module_load(bdata(conf_style)) == 0, "Error loading config module: %s", bdata(conf_style));
        check(CONFIG_MODULE.init(bdata(conf_url)) == 0, "Error loading config url: %s", bdata(conf_url));
    }

    return 0;
error:
    return -1;

}

int Command_servers(Command *cmd)
{
    tns_value_t *res = NULL;
    int rc = 0;
    check(open_config(cmd) == 0, "Error opening configuration");

    printf("SERVERS:\n------\n");
    const int columns[] = {10, //name
                            2,  //default_host
                            1,  // uuid
                           -1 };
    res = CONFIG_MODULE.load_server(NULL);
    rc =  simple_res_print(res, columns);
error:
    if (res) tns_value_destroy(res);
    return rc;
}

int Command_hosts(Command *cmd)
{
    bstring server_name = option(cmd, "server", NULL);
    tns_value_t *host_res = NULL;
    tns_value_t *res = NULL;
    int rc = 0;
    int columns[] = {0, //id
                     1, // name
                    -1};

    check(open_config(cmd) ==0 , "Error opening configuration");
    check(server_name, "You need to give a -server of the server to list hosts from.");

    host_res = tns_filter_str_field(CONFIG_MODULE.load_server(NULL), server_name, 10);

    int cols;
    int rows = DB_counts(host_res, &cols);
    int i;
    if (rows == 0)
        log_warn("No results to display.");
    for (i = 0; i < rows; i++) {
        bstring uuid = DB_get(host_res, i,1)->value.string;
        int id = DB_get(host_res, i,0)->value.number;
        printf("\nHOSTS in %s (%s):\n-----\n", bdata(server_name), bdata(uuid));
        
        res = CONFIG_MODULE.load_hosts(id);
        rc = simple_res_print(res, columns);
        if (rc != 0)
            break;
        tns_value_destroy(res);
        res = NULL;
    }

error: // fallthrough
    if(res) tns_value_destroy(res);
    if(host_res) tns_value_destroy(host_res);
    return rc;
}


int Command_routes(Command *cmd)
{
    bstring server = option(cmd, "server", NULL);
    bstring host = option(cmd, "host", NULL);
    bstring host_id = option(cmd, "id", NULL);
    tns_value_t *res = NULL;
    tns_value_t *server_res = NULL;
    tns_value_t *host_res = NULL;
    int rc = 0;
    int columns[] = {1, //path
                  -1};

    check(open_config(cmd) ==0 , "Error opening configuration");

    if(host_id) {
        printf("ROUTES in host id %s\n-----\n", bdata(host_id));

        // find server_id
        server_res = CONFIG_MODULE.load_server(NULL);
        int cols;
        int rows = DB_counts(server_res, &cols);
        int i;
        int server_id = -1;
        char *end_ptr = NULL;
        int ihost_id = strtol(bdata(host_id),&end_ptr,10);
        for (i=0; i< rows && server_id == -1; i++) {
            host_res = CONFIG_MODULE.load_hosts(DB_get(server_res, i, 0)->value.number);
            int host_rows = DB_counts(host_res, &cols);
            int j;
            for (j=0; j< host_rows;j++) {
                if (DB_get(host_res,j,0)->value.number == ihost_id) {
                    server_id = DB_get(server_res, i, 0)->value.number;
                    break;
                }
            }
            tns_value_destroy(host_res);
            host_res = NULL;
        }
        tns_value_destroy(server_res);
        server_res = NULL;
        if (server_id == -1) {
            log_warn("No host_id matching %d", ihost_id);
            return 0;
        }

        res = CONFIG_MODULE.load_routes(ihost_id, server_id);
        rc = simple_res_print(res, columns);
    } else {
        check(server, "Must set the -server name you want or use -id.");
        check(host, "Must set the -host in that server you want or use -id.");

        server_res = tns_filter_str_field(CONFIG_MODULE.load_server(NULL), server, 10);
        int cols;
        int rows = DB_counts(server_res, &cols);
        int i;
        for (i=0; i< rows; i++) {
            bstring uuid = DB_get(server_res, i, 1)->value.string;
            int server_id = DB_get(server_res, i, 0)->value.number;
            host_res = CONFIG_MODULE.load_hosts(server_id);          
            host_res = tns_filter_str_field(host_res, host, 1);            
            int host_rows = DB_counts(host_res, &cols);
            int j;
            for (j=0; j< host_rows;j++) {
                int ihost_id = DB_get(host_res, j, 0)->value.number;
                res = CONFIG_MODULE.load_routes(ihost_id, server_id);
                printf("\nROUTES in host %s, server %s (%s) \n-----\n", bdata(host), bdata(server), bdata(uuid));
                rc = simple_res_print(res, columns);
                if (rc != 0)
                    break;
                tns_value_destroy(res);
                res = NULL;
            }
            if (rc != 0)
                break;
            tns_value_destroy(host_res);
            host_res = NULL;
        }
        
        tns_value_destroy(server_res);
        server_res = NULL;

    }

error: //fallthrough
    if(res) tns_value_destroy(res);
    if(host_res) tns_value_destroy(host_res);
    if(server_res) tns_value_destroy(server_res);
    return rc;
}


