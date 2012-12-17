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

#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <zmq.h>

#include <tnetstrings.h>
#include <tnetstrings_impl.h>
#include <config/db.h>
#include <handler.h>
#include <pattern.h>
#include <register.h>

#include "../linenoise.h"
#include "../commands.h"
#include "../query_print.h"
#include "logging.h"
#include "running.h"

struct ServerRun {
    int ran;
    bstring db_file;
    bstring config_url;
    bstring config_style;
    bstring uuid;
    const char *sudo;
    int murder;
};

typedef struct child_t {
    int id;
    lnode_t *node;
    FILE *stream;
    pid_t pid;
    bstring uuid;
} child_t;

volatile sig_atomic_t termination_in_progress = 0;
volatile list_t *termination_child_list = NULL;
//FROM: http://www.gnu.org/software/libc/manual/
void
termination_handler (int sig)
{
    /* Since this handler is established for more than one kind of signal,
      it might still get invoked recursively by delivery of some other kind
      of signal.  Use a static variable to keep track of that. */
    if (termination_in_progress)
        raise (sig);
    termination_in_progress = 1;
    log_info("Caught signal. Terminating...");
    if (termination_child_list) {
        child_t *child;
        lnode_t *node;
        for (node = list_first(termination_child_list);
             node != NULL;
             node = list_next(termination_child_list,node))
        {
            child = (child_t *) lnode_get(node);
            if (child) {
                log_info("UUID %s: Killing...", bdata(child->uuid));
                kill(child->pid, sig);
            }
        }
    }

    /* Now reraise the signal.  We reactivate the signal's
      default handling, which is to terminate the process.
      We could just call exit or abort,
      but reraising the signal sets the return status
      from the process correctly. */
    signal (sig, SIG_DFL);
    raise (sig);
}

//FROM: http://www.gnu.org/software/libc/manual/
static int install_signal_handler(list_t *child_list) {
    termination_child_list = child_list;
    if (signal (SIGINT, termination_handler) == SIG_IGN)
      signal (SIGINT, SIG_IGN);
    if (signal (SIGHUP, termination_handler) == SIG_IGN)
      signal (SIGHUP, SIG_IGN);
    if (signal (SIGTERM, termination_handler) == SIG_IGN)
      signal (SIGTERM, SIG_IGN);
    if (signal (SIGQUIT, termination_handler) == SIG_IGN)
      signal (SIGQUIT, SIG_IGN);
    return 0;
}

static int uninstall_signal_handler() {
    termination_child_list = NULL;
    if (signal (SIGINT, SIG_DFL) == SIG_IGN)
      signal (SIGINT, SIG_IGN);
    if (signal (SIGHUP, SIG_DFL) == SIG_IGN)
      signal (SIGHUP, SIG_IGN);
    if (signal (SIGTERM, SIG_DFL) == SIG_IGN)
      signal (SIGTERM, SIG_IGN);
    if (signal (SIGQUIT, SIG_DFL) == SIG_IGN)
      signal (SIGQUIT, SIG_IGN);
    return 0;
}

static int block_signals() {
    sigset_t block_term;

    sigemptyset (&block_term);
    sigaddset (&block_term, SIGINT);
    sigaddset (&block_term, SIGHUP);
    sigaddset (&block_term, SIGTERM);
    sigaddset (&block_term, SIGQUIT);
    sigprocmask (SIG_BLOCK, &block_term, NULL);
    return 0;
}

static int unblock_signals() {
    sigset_t block_term;

    sigemptyset (&block_term);
    sigaddset (&block_term, SIGINT);
    sigaddset (&block_term, SIGHUP);
    sigaddset (&block_term, SIGTERM);
    sigaddset (&block_term, SIGQUIT);
    sigprocmask (SIG_UNBLOCK, &block_term, NULL);
    return 0;
}

static inline int exec_server_operations(Command *cmd,
        int (*callback)(struct ServerRun *, tns_value_t *), const char *select)
{
    int rc = 0;
    tns_value_t *res = NULL;

    bstring db_file = option(cmd, "db", NULL);
    bstring conf_url = option(cmd, "url", NULL);
    bstring conf_style = option(cmd, "style", NULL);
    bstring uuid = option(cmd, "uuid", NULL);

    if(conf_url == NULL && db_file == NULL) {
        db_file = bfromcstr("config.sqlite");
    }

    check(db_file != NULL || (conf_url != NULL && conf_style != NULL),
            "You must give either --db or --style and --url.");

    struct ServerRun run = {
        .ran = 0,
        .db_file = db_file,
        .config_url = conf_url,
        .config_style = conf_style,
        .sudo = "",
        .uuid = uuid,
        .murder = 0
    };

    bstring name = option(cmd, "name", NULL);
    bstring host = option(cmd, "host", NULL);
    bstring sudo = option(cmd, "sudo", NULL);
    bstring every = option(cmd, "every", NULL);
    run.murder = option(cmd, "murder", NULL) != NULL;

    int option_count =  (name != NULL) + (host != NULL) + (uuid != NULL);
    check(option_count <= 1, "Just one please, not all of the options.");

    if(sudo) {
        run.sudo = biseqcstr(sudo, "") ? "sudo" : bdata(sudo);
    } else {
        run.sudo = "";
    }

    if(db_file != NULL) {
        rc = DB_init(bdata(db_file));
        check(rc == 0, "Failed to open db: %s", bdata(db_file));

        if(name) {
            res = DB_exec("SELECT %s FROM server where name = %Q", select, bdata(name));
        } else if(host) {
            res = DB_exec("SELECT %s FROM server where default_host = %Q", select, bdata(host));
        } else if(uuid) {
            res = DB_exec("SELECT %s FROM server where uuid = %Q", select, bdata(uuid));
            check(darray_end(res->value.list) == 1, "Cannot have more than one server with the same uuid %s", bdata(uuid));
        } else {
            res = DB_exec("SELECT %s FROM server", select);
        }
        debug("Found %d servers", darray_end(res->value.list));
        check(tns_get_type(res) == tns_tag_list,
                "Wrong return type from query, should be list.");
        check(darray_end(res->value.list) > 0, "No servers matched the description.");
        check(darray_end(res->value.list) == 1 || every, "Found multiple servers. Please use '-every' option to specify all of them");
    }

    check(callback(&run, res) != -1, "Failed to run internal operation.");

    if(!run.ran) {
        errno = 0;

        if(every) {
            log_err("You specified -every server but didn't load any. Not configured right?");
        } else if(host) {
            log_err("Could not load server with host '%s' from db %s.", bdata(host), bdata(db_file));
        } else if(uuid) {
            log_err("Could not load server with uuid '%s' from db %s.", bdata(uuid), bdata(db_file));
        } else if(name) {
            log_err("Could not load server named '%s' from db %s.", bdata(name), bdata(db_file));
        } else {
            log_err("Well looks like you broke something, please report what you did to mongrel2.org.");
        }

        sentinel("Error loading the requested server, see above for why.");
    }

    if(res) tns_value_destroy(res);
    DB_close();
    return 0;

error:
    if(res) tns_value_destroy(res);
    DB_close();
    return -1;
}

void destroy_child(child_t *child)
{
    if  (child->pid) {
        log_info("UUID %s: Killing due to error", child->uuid);
        kill(child->pid, SIGTERM);
    }
    if (child->stream) {
        fclose(child->stream);
    }
    if (child->uuid) {
        bdestroy(child->uuid);
        child->uuid = NULL;
    }
    free (child);

}

//FROM: http://www.gnu.org/software/libc/manual/
int set_nonblock_flag(int fd, int value)
{
    int oldflags = fcntl (fd, F_GETFL, 0);
    /* If reading the flags failed, return error indication now. */
    if (oldflags == -1)
     return -1;
    /* Set just the flag we want to set. */
    if (value != 0)
       oldflags |= O_NONBLOCK;
    else
       oldflags &= ~O_NONBLOCK;
    /* Store modified flag word in the descriptor. */
    return fcntl (fd, F_SETFL, oldflags);
}

/* Returns:
  -1: error
   0: child_deleted
   1: all good
*/
static int process_child_data(list_t *child_list, child_t * child)
{
    //TODO: Little more errorchecking
    static int last_id=-1;
    int status;
    int result;
    char *line = NULL;
    size_t line_size = 0;
    int new_line = 1;
    debug("UUID %s: processing data", bdata(child->uuid));
    set_nonblock_flag(fileno(child->stream),1);
    while (1) {
        if (line)
            free(line);
        line = NULL;
        line_size = 0;
        result = getline(&line, &line_size, child->stream);
        if (result > 0) {
            if (child->id != last_id) {
                last_id = child->id;
                fprintf(dbg_get_log(), "(%d) UUID: %s\n", child->id, bdata(child->uuid));
            }
            if (new_line) {
                fprintf(dbg_get_log(), "    (%d) %s", child->id, line);
            } else {
                fprintf(dbg_get_log(), "%s", line);
            }
            new_line = (line[result-1] == '\n');
        }
        if (result == 0)
            break;
        if (ferror(child->stream) && errno == EAGAIN) {
            // no more data available. Clear Error (very important)
            clearerr(child->stream);
            errno=0;
            debug("UUID %s: getline EAGAIN", bdata(child->uuid));

            break;
        }
        if (feof(child->stream) || ferror(child->stream)) {
            // child dead
            result = waitpid(child->pid, &status, WNOHANG);
            if (!(result == 0 || (result == -1 && errno == ECHILD)) ) {
                log_err("UUID %s: Child stream died but not child. Killing.", bdata(child->uuid));
                kill(child->pid, SIGTERM);
            }
            if (WIFEXITED(status)) {
                log_info("UUID %s: Exited with status: %d", bdata(child->uuid), WEXITSTATUS(status));
            } else {
                log_info("UUID %s: Exited abnormally", bdata(child->uuid));
            }
            block_signals();
            list_delete(child_list, child->node);
            unblock_signals();
            lnode_destroy(child->node);
            child->node = NULL;
            child->pid = (pid_t) 0;
            destroy_child(child);
            child = NULL;
            errno=0;
            return 0;
        }
    }
    if (line)
        free(line);


    set_nonblock_flag(fileno(child->stream),0);
    
    if (!new_line) {
        fprintf(dbg_get_log(), " \\\n");
    }
    return 1;

error:
    return -1;

}

static int process_children_data(list_t *child_list)
{
    //TODO: error checking
    fd_set child_set;
    lnode_t *node;
    child_t *child;
    int result;
    int file_no;

    FD_ZERO(&child_set);

    for (node = list_first(child_list); node != NULL; node = list_next(child_list, node)) {
        child = (child_t *) lnode_get(node);
        file_no = fileno(child->stream);
        FD_SET( file_no,&child_set);
    }

    // continue while there are streams to read from
    debug("Starting children processing");
    while (!list_isempty(child_list)) {
        fd_set rd_set,ex_set;
        memcpy(&rd_set, &child_set, sizeof(fd_set));
        memcpy(&ex_set, &child_set, sizeof(fd_set));
        debug("Blocking select %d", child_set);
        result = select(FD_SETSIZE, &rd_set, NULL, &ex_set, NULL);
        check(result != -1, "select failed");
        debug("Select returned %d", result);
        for (node = list_first(child_list); node != NULL; node = list_next(child_list, node)) {
            child = (child_t *) lnode_get(node);
            file_no = fileno(child->stream);
            if (FD_ISSET(file_no, &rd_set) || FD_ISSET(file_no, &ex_set)) {
                result = process_child_data(child_list, child);
                if (result == 0) {
                    //child died. Clear stream
                    FD_CLR(file_no, &child_set);
                    break;
                }
            }
        }

    }
    return 0;

error:
    return 1;
}


int run_mongrel2(struct ServerRun *r, const_bstring config, const_bstring uuid, const_bstring module)
{
    bstring command = bformat("%s mongrel2 %s %s %s",
            r->sudo, bdata(config), bdata(uuid), bdata(module));
    debug("Running mongrel: %s", bdata(command));
    system(bdata(command));
    bdestroy(command);
    return 1;
}




child_t * start_child_server(list_t *child_list, struct ServerRun *r,
                             const_bstring config,
                             const_bstring uuid,
                             const_bstring module)
{
    int child_pipe[2] = {0,0};
    child_t *child = NULL;
    lnode_t *child_node = NULL;

    child = calloc( 1,sizeof(child_t));
    check_mem(child);
    child_node = lnode_create(child);
    check_mem(child_node);
    child->node = child_node;
    child->uuid = bstrcpy(uuid);
    child->id = list_count(child_list);
    check_mem(child->uuid);

    check(pipe(child_pipe) == 0, "UUID %s: Failed to create child pipe", bdata(uuid));
    //check(set_nonblock_flag(child_pipe[0],0) != -1, "UUID %s: Failed to unset nonblocking on child pipe", bdata(uuid));
    child->stream = fdopen(child_pipe[0], "r");
    setvbuf(child->stream, NULL, _IONBF,0);
    check(child->stream != NULL, "UUID %s: Failed to create child stream", bdata(uuid));
    child_pipe[0] = 0; // use child->stream instead

    block_signals();
    {
        pid_t child_pid = fork();
        check(child_pid != (pid_t) -1, "UUID %s: Failed to fork child");
        if (child_pid == (pid_t) 0) {
            //in child
            uninstall_signal_handler();
            unblock_signals();

            fclose(child->stream);
            dup2(child_pipe[1], STDERR_FILENO);

            exit(run_mongrel2(r, config, child->uuid, module));
        }
        // in parent
        child->pid = child_pid;
        list_append(child_list, child_node);
    }
    unblock_signals();

    close(child_pipe[1]);
    child_pipe[1] = 0;
    return child;
error:

    if (child && child->pid != (pid_t) 0) {
        block_signals();
        list_delete(child_list, child->node);
    }
    if (child)
        destroy_child(child);

    unblock_signals();
    if (child_pipe[0]) {
        close(child_pipe[0]);
    }
    if (child_pipe[1]) {
        close(child_pipe[1]);
    }
    if (child_node) {
        lnode_destroy(child_node);
    }
    return NULL;
}



static int run_server(struct ServerRun *r, tns_value_t *res)
{
    r->ran = 0;
    bstring config = NULL;
    bstring module = NULL;
    bstring uuid = NULL;
    int rows = 1;
    list_t child_list;

    if(r->db_file) {
        DB_check(res, 0, 1, tns_tag_string);
        tns_value_t *uuid_val = DB_get(res, 0, 0);
        config = bstrcpy(r->db_file);
        module = bfromcstr("");
        uuid = bstrcpy(uuid_val->value.string);
        rows = darray_end(res->value.list);
    } else {
        config = bstrcpy(r->config_url);
        module = bstrcpy(r->config_style);
        uuid = bstrcpy(r->uuid);
        rows = 1;
    }

    if (rows > 1) {
        child_t * child;
        int row;

        list_init(&child_list, LISTCOUNT_T_MAX);
        check(install_signal_handler(&child_list) == 0, "Cannot create signal handler");

        for (row = 0; row < rows; row++) {
            tns_value_t *uuid_val = DB_get(res, row, 0);
            bdestroy(uuid);
            uuid = bstrcpy(uuid_val->value.string);
            debug("Starting server %d (UUID %s)", row, bdata(uuid));
            child = start_child_server(&child_list, r, config, uuid, module);
            if (child == NULL) {
                log_err("UUID %s: Error creating child server", bdata(uuid));
                errno = 0;
                continue;
            }
            sleep(1);
            check(process_child_data(&child_list, child) != -1, "UUID %s: Error processing child data.", bdata(uuid));

        }

        check(process_children_data(&child_list) ==0, "Error processing children data");
        uninstall_signal_handler();
        assert(list_isempty(&child_list));
        r->ran = 1;
    } else {
        r->ran = run_mongrel2(r, config, uuid, module);
    }

    bdestroy(config);
    bdestroy(module);
    bdestroy(uuid);

    return 0;

error:
    bdestroy(config);
    bdestroy(module);
    bdestroy(uuid);

    if (rows > 1) {
        lnode_t *node;
        for (node = list_first(&child_list); node != NULL; node = list_next(&child_list, node)) {
            child_t *child = (child_t *) lnode_get(node);
            if (child) {
                block_signals();
                lnode_put(node, NULL);
                destroy_child(child);
                unblock_signals();
            }
        }
        block_signals();
        list_destroy_nodes(&child_list);
        uninstall_signal_handler();
        unblock_signals();

    }
    return -1;
}




int Command_start(Command *cmd)
{
    return exec_server_operations(cmd, run_server, "uuid");
}

bstring read_pid_file(bstring pid_path)
{
    FILE *pid_file = fopen(bdata(pid_path), "r");
    bstring pid = NULL;

    if(pid_file == NULL) {
        return NULL;
    } else {
        pid = bread((bNread)fread, pid_file);
        fclose(pid_file); pid_file = NULL;
    }

    return pid;
}

static int locate_pid_file(tns_value_t *res)
{
    bstring pid = NULL;
    bstring pid_path = NULL;

    int cols = 0;
    int rows = DB_counts(res, &cols);
    check(rows == 1 && cols == 2, "Wrong number of results.");

    tns_value_t *chroot = DB_get(res, 0, 0);
    check(tns_get_type(chroot) == tns_tag_string, "Wrong result for server chroot, should be a string.");

    tns_value_t *pid_file = DB_get(res, 0, 1);
    check(tns_get_type(pid_file) == tns_tag_string, "Wrong result for server pid_file, should be a string.");

    pid_path = bformat("%s%s", bdata(chroot->value.string), bdata(pid_file->value.string));

    pid = read_pid_file(pid_path);
    check(pid, "Couldn't read the PID from %s", bdata(pid_path));

    int result = atoi((const char *)pid->data);

    bdestroy(pid);
    bdestroy(pid_path);
    return result;

error:
    bdestroy(pid);
    bdestroy(pid_path);
    return -1;
}

static int kill_server(struct ServerRun *r, tns_value_t *res, int signal)
{
    int pid = locate_pid_file(res);
    check(pid != -1, "Failed to read the pid_file.");

    int rc = kill(pid, signal);
    check(rc == 0, "Failed to stop server with PID: %d", pid);

    r->ran = 1;
    return 0;

error:
    r->ran = 0;
    return -1;
}


static int stop_server(struct ServerRun *r, tns_value_t *res)
{
    int signal = r->murder ? SIGTERM : SIGINT;
    return kill_server(r, res, signal);
}

int Command_stop(Command *cmd)
{
    return exec_server_operations(cmd, stop_server, "chroot, pid_file");
}

static int reload_server(struct ServerRun *r, tns_value_t *res)
{
    return kill_server(r, res, SIGHUP);
}

int Command_reload(Command *cmd)
{
    return exec_server_operations(cmd, reload_server, "chroot, pid_file");
}

static int check_server(struct ServerRun *r, tns_value_t *res)
{
    int rc = 0;
    int pid = locate_pid_file(res);

    if(pid == -1) {
        printf("mongrel2 is not running because pid_file isn't there.\n");
        r->ran = 1;
        return 0;
    }

    errno = 0;
    rc = kill(pid, 0);

    if((rc != 0) && (errno == ESRCH)) {
        printf("mongrel2 at PID %d is NOT running.\n", pid);
    } else if ((rc == 0) || (errno == EPERM)) {
        printf("mongrel2 at PID %d running.\n", pid);
    } else {
        sentinel("Could not send signal to mongrel2 at PID %d", pid);
    }

    r->ran = 1;
    return 0;

error:
    r->ran = 0;
    return -1;
}

int Command_running(Command *cmd)
{
    return exec_server_operations(cmd, check_server, "chroot, pid_file");
}

static inline int linenoise_runner(const char *prompt, int (*callback)(bstring arg, void *data), void *data)
{
    char *line = NULL;
    bstring args = NULL;
    char *home_dir = getenv("HOME");
    bstring hist_file = NULL;

    if(home_dir != NULL) {
        hist_file = bformat("%s/.m2sh", home_dir);
        linenoiseHistoryLoad(bdata(hist_file));
    } else {
        log_warn("You don't have a HOME environment variable. Oh well, no history.");
        hist_file = NULL;
    }

    while((line = linenoise(prompt)) != NULL) {
        if (line[0] != '\0') {
            args = bformat("%s", line);
            callback(args, data);
            bdestroy(args);

            if(hist_file) {
                linenoiseHistoryAdd(line);
                linenoiseHistorySave(bdata(hist_file)); /* Save every new entry */
            }
        }

        free(line);
    }

    bdestroy(hist_file);
    return 0;
}

static struct tagbstring TOKENS = bsStatic(" \t\n=");
static struct tagbstring NUMBER_PATTERN = bsStatic("[\\-0-9]+");
bstring parse_input(bstring inbuf)
{
    size_t len = 0;
    int i = 0;
    char *data = NULL;
    bstring result = NULL;
    tns_value_t *req = tns_new_list();
    tns_value_t *args = tns_new_dict();
    tns_value_t *value = NULL;

    btrimws(inbuf);
    struct bstrList *list = bsplits(inbuf, &TOKENS);
    check((list->qty + 1) % 2 == 0, "USAGE: command arg1=val1 arg2=val2");

    tns_add_to_list(req,
            tns_parse_string(bdata(list->entry[0]), blength(list->entry[0])));

    for(i = 1; i < list->qty; i += 2) {
        bstring key_str = list->entry[i];
        bstring val_str = list->entry[i+1];
        tns_value_t *key = tns_parse_string(bdata(key_str), blength(key_str));

        if(bstring_match(val_str, &NUMBER_PATTERN)) {
            value = tns_parse_integer(bdata(val_str), blength(val_str));
        } else {
            value = tns_parse_string(bdata(val_str), blength(val_str));
        }

        tns_add_to_dict(args, key, value);
    }

    tns_add_to_list(req, args);

    data = tns_render(req, &len);
    check(data != NULL, "Didn't render to a valid TNetstring.");
    check(len > 0, "Didn't create a valid TNetstring.");

    result = blk2bstr(data, len);
    check(result != NULL, "Couldn't convert to string.");

    tns_value_destroy(req);
    bstrListDestroy(list);
    free(data);
    return result;

error:

    if(req) tns_value_destroy(req);
    if(list) bstrListDestroy(list);
    if(data) free(data);
    if(result) bdestroy(result);

    return NULL;
}

static void bstring_free(void *data, void *hint)
{
    bdestroy((bstring)hint);
}

struct tagbstring ERROR_KEY = bsStatic("error");
struct tagbstring HEADERS_KEY = bsStatic("headers");
struct tagbstring ROWS_KEY = bsStatic("rows");

static void display_map_style(tns_value_t *headers, tns_value_t *table)
{
    int i = 0;
    int cols = 0;
    int rows = DB_counts(table, &cols);
    check(rows != -1, "Invalid query result, probably not a table.");
    darray_t *names = headers->value.list;

    check(cols == darray_end(names),
            "Server returned a bad result, names isn't same length as elements.");

    if(rows == 1) {
        for(i = 0; i < cols; i++)
        {
            tns_value_t *h = darray_get(names, i);
            tns_value_t *val = DB_get(table, 0, i);
            check(tns_get_type(h) == tns_tag_string, "Headers should be strings.");
            check(tns_get_type(val) != tns_tag_invalid,
                    "Invalid value for column %d of result.", i);

            print_datum(h);
            printf(":  ");
            print_datum(val);
            printf("\n");
        }
    } else {
        sentinel("Asked to display something that's not in map style.");
    }

error: // fallthrough
    return;
}


void display_table_style(tns_value_t *headers, tns_value_t *table)
{
    int col_i = 0;
    int row_i = 0;
    for(col_i = 0; col_i < darray_end(headers->value.list); col_i++)
    {
        tns_value_t *h = darray_get(headers->value.list, col_i);
        check(tns_get_type(h) == tns_tag_string,
                "Headers should be strings, not: %c", tns_get_type(h));
        printf("%s  ", bdata(h->value.string));
    }
    printf("\n");

    int cols = 0;
    int rows = DB_counts(table, &cols);
    check(rows != -1, "Invalid query results, probably not in table format.");

    for(row_i = 0; row_i < rows; row_i++) {
        for(col_i = 0; col_i < cols; col_i++) {
            tns_value_t *col = DB_get(table, row_i, col_i);
            print_datum(col);
            printf("  ");
        }
        printf("\n");
    }
    printf("\n");

error: // fallthrough
    return;
}

void display_response(const char *msg, size_t len)
{
    tns_value_t *resp = tns_parse(msg, len, NULL);
    hnode_t *node = NULL;

    check(tns_get_type(resp) == tns_tag_dict, "Server returned an invalid response, must be a dict.");

    node = hash_lookup(resp->value.dict, &ERROR_KEY);

    if(node) {
        tns_value_t *val = hnode_get(node);
        printf("ERROR: %s\n", bdata(val->value.string));
    } else {
        node = hash_lookup(resp->value.dict, &HEADERS_KEY);
        check(node != NULL, "Server returned an invalid response, need a 'headers'.");
        tns_value_t *headers = hnode_get(node);
        check(tns_get_type(headers) == tns_tag_list, "Headers must be a list, server is screwed up.");

        node = hash_lookup(resp->value.dict, &ROWS_KEY);
        check(node != NULL, "Server returned an invalid response, need a 'rows'.");
        tns_value_t *rows = hnode_get(node);
        check(tns_get_type(rows) == tns_tag_list, "Rows must be a list, server is screwed up.");

        if(darray_end(rows->value.list) == 1) {
            display_map_style(headers, rows);
        } else {
            display_table_style(headers, rows);
        }
    }

error: // fallthrough
    tns_value_destroy(resp);
    return;
}

int send_recv_control(bstring args, void *socket)
{
    int rc = 0;
    zmq_msg_t *outmsg = NULL;
    zmq_msg_t *inmsg = NULL;

    outmsg = calloc(sizeof(zmq_msg_t), 1);
    check_mem(outmsg);
    inmsg = calloc(sizeof(zmq_msg_t), 1);
    check_mem(inmsg);
    
    rc = zmq_msg_init(outmsg);
    check(rc == 0, "Failed to initialize outgoing message.");
    rc = zmq_msg_init(inmsg);
    check(rc == 0, "Failed to initialize incoming message.");

    bstring request = parse_input(args);
    check(request != NULL, "Invalid command, try again.");

    // send the message
    rc = zmq_msg_init_data(outmsg, bdata(request), blength(request)+1, bstring_free, request);
    check(rc == 0, "Failed to init outgoing message.");

    rc = mqsend(socket, outmsg, 0);
    check(rc == 0, "Failed to send message to control port.");
    free(outmsg);

    // recv the response
    rc = mqrecv(socket, inmsg, 0);
    check(rc == 0, "Failed to receive message from control port.");

    display_response((const char *)zmq_msg_data(inmsg), zmq_msg_size(inmsg));

    fflush(stdout);
    free(inmsg);

    return 0;

error:
    if(outmsg) free(outmsg);
    if(inmsg) free(inmsg);
    return -1;
}

int control_server(struct ServerRun *r, tns_value_t *res)
{
    int rc = 0;
    void *socket = NULL;
    bstring prompt = NULL;
    bstring control = NULL;
    r->ran = 1;
    int cols = 0;
    int rows = DB_counts(res, &cols);

    check(rows != -1, "Invalid data given to internal routine control_server.");
    check(rows == 1, "Ambiguous server select, expected 1 but got %d.", rows);

    bstring server_name = DB_get_as(res, 0, 0, string);
    bstring chroot = DB_get_as(res, 0, 1, string);

    check(server_name != NULL && chroot != NULL, 
            "Somehow didn't get a good server_name and chroot.");

    prompt = bformat("m2 [%s]> ", bdata(server_name));
    control = bformat("ipc://%s/run/control", bdata(chroot));
    log_info("Connecting to control port %s", bdata(control));

    mqinit(1);
    Register_init();

    socket = mqsocket(ZMQ_REQ);
    check(socket != NULL, "Failed to create REQ socket.");

    rc = zmq_connect(socket, bdata(control));
    check(rc == 0, "Failed to connect to control port.");

    rc = linenoise_runner(bdata(prompt), send_recv_control, socket);

    bdestroy(prompt);
    bdestroy(control);
    zmq_close(socket);
    zmq_term(ZMQ_CTX);
    return rc;

error:
    if(prompt) bdestroy(prompt);
    if(control) bdestroy(control);
    if(socket) zmq_close(socket);
    return -1;
}

int Command_control(Command *cmd)
{
    return exec_server_operations(cmd, control_server, "name, chroot");
}

static int run_command(bstring line, void *ignored)
{
    bstring args = bformat("m2sh %s", bdata(line));
    int rc = Command_run(args);

    bdestroy(args);
    return rc;
}

int Command_shell(Command *cmd)
{
    return linenoise_runner("mongrel2> ", run_command, NULL);
}

