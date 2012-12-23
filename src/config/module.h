#ifndef _module_h
#define _module_h

#include "tnetstrings.h"

typedef struct ConfigModule {

    int (*init)(const char *path);
    void (*close)();
    tns_value_t *(*load_handler)(int handler_id);
    tns_value_t *(*load_proxy)(int proxy_id);
    tns_value_t *(*load_dir)(int dir_id);
    tns_value_t *(*load_routes)(int host_id, int server_id);
    tns_value_t *(*load_hosts)(int server_id);
    tns_value_t *(*load_filters)(int server_id);
    tns_value_t *(*load_xrequests)(int server_id);
    tns_value_t *(*load_server)(const char *uuid);
    tns_value_t *(*load_mimetypes)();
    tns_value_t *(*load_settings)();
    //transactions
    int supports_transactions;
    int (*begin) ();
    int (*commit) ();
    //saving
    int supports_save;
    int (*remake_schema)();
    int (*save_handler)(tns_value_t *data);
    int (*save_proxy)(tns_value_t *data);
    int (*save_dir)(tns_value_t *data);
    int (*save_route)(tns_value_t *data);
    int (*save_host)(tns_value_t *data);
    int (*save_filter)(tns_value_t *data);
    int (*save_xrequest)(tns_value_t *data);
    int (*save_server)(tns_value_t *data);
    int (*save_mimetype)(tns_value_t *data);
    int (*save_setting)(tns_value_t *data);
} ConfigModule;

extern ConfigModule CONFIG_MODULE;

#endif
