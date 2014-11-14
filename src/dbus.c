#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include <libchain/libchain.h>
#include <dbus/dbus.h>

#include "chaind.h"
#include "dbus.h"
#include "dbus-block.h"
#include "logging.h"

#include "introspection/chaind.h"

struct dbus {
    struct chaind* state;
    DBusConnection* conn;

    unsigned int next_watch_id;
    void* watches;

    unsigned int next_block_connected_signal_id;
};

static DBusHandlerResult filter_message(DBusConnection*, DBusMessage*, void*);

static DBusHandlerResult handle_chaind_message(DBusConnection*, DBusMessage*, void*);

static struct DBusObjectPathVTable chaind_vtable = {
    NULL, handle_chaind_message, NULL, NULL, NULL, NULL
};

static dbus_bool_t add_timeout(DBusTimeout *to, void *userdata)
{
    printf("dbus add_timeout\n");
    assert(0);
    return TRUE;
}

static void remove_timeout(DBusTimeout *to, void *userdata)
{
    printf("dbus remove_timeout\n");
    assert(0);
}

static void toggle_timeout(DBusTimeout *to, void *userdata)
{
    printf("dbus toggle_timeout\n");
    assert(0);
}

static dbus_bool_t add_watch(DBusWatch* watch, void *userdata)
{
    struct dbus* dbus = (struct dbus*)userdata;

    Word_t index = (Word_t)dbus->next_watch_id;
    DBusWatch** pwatch;
    JLI(pwatch, dbus->watches, index);
    assert_pointer(pwatch);
    *pwatch = watch;
    dbus->next_watch_id += 1;

    return TRUE;
}

static void remove_watch(DBusWatch* watch, void *userdata)
{
    struct dbus* dbus = (struct dbus*)userdata;

    Word_t index = 0;
    DBusWatch** pwatch;

    JLF(pwatch, dbus->watches, index);
    while(pwatch != NULL) {
        if(*pwatch == watch) {
            Word_t wrc;
            JLD(wrc, dbus->watches, index);
            break;
        }
        JLN(pwatch, dbus->watches, index);
    }
}

static void watch_toggled(DBusWatch* watch, void *userdata)
{
    // We don't need to do anything. the next update() will 
    // see that the watch is enabled/disabled.
}

struct dbus* dbus_start_service(struct chaind* state)
{
    struct dbus* dbus = (struct dbus*)malloc(sizeof(struct dbus));
    zero(dbus);

    dbus->state = state;

    // Try connecting to the system bus (if we're root), and if we fail, try the session bus.
    DBusError err;
    dbus_error_init(&err);

    for(int attempt = 0; attempt < 2; attempt++) {
        dbus->conn = dbus_bus_get(attempt == 0 ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION, &err);
        if(dbus_error_is_set(&err)) {
            log_warning("cannot connect to %s bus: %s", (attempt == 0) ? "system" : "session", err.message);
            goto error;
        }

        if(dbus->conn == NULL) {
            log_warning("cannot connect to %s bus", (attempt == 0) ? "system" : "session");
            goto error;
        }

        // Register the block/tx filter
        if(!dbus_connection_add_filter(dbus->conn, filter_message, (void*)dbus, NULL)) {
            log_warning("cannot register message filter");
            goto error;
        }

        // Register the object before requesting a name
        dbus_connection_register_object_path(dbus->conn, "/org/sarcharsoftware/chaind", &chaind_vtable, (void*)dbus);

        int ret = dbus_bus_request_name(dbus->conn, "org.sarcharsoftware.chaind", 0, &err);
        if(dbus_error_is_set(&err)) {
            log_warning("couldn't claim primary name org.sarcharsoftware.chaind: %s", err.message);
            dbus_connection_unref(dbus->conn);
            dbus->conn = NULL;
            dbus_error_free(&err);
            dbus_error_init(&err);
            continue;
        }

        if(ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
            log_warning("couldn't claim primary name org.sarcharsoftware.chaind: not the primary owner", err.message);
            goto error;
        }

        log_debug("dbus connected to %s bus", (attempt == 0) ? "system" : "session");
        break;
    }

    if(!dbus_connection_set_timeout_functions(dbus->conn, add_timeout, remove_timeout, toggle_timeout, (void*)dbus, NULL)) {
        goto error;
    }

    if(!dbus_connection_set_watch_functions(dbus->conn, add_watch, remove_watch, watch_toggled, (void*)dbus, NULL)) {
        goto error;
    }

    dbus_error_free(&err);
    return dbus;
error:
    dbus_destroy_service(dbus);
    return NULL;
}

void dbus_destroy_service(struct dbus* dbus)
{
    Word_t wrc;
    JLFA(wrc, dbus->watches);

    if(dbus->conn != NULL) dbus_connection_unref(dbus->conn);
    free(dbus);
}

static int get_pollfds(struct dbus* dbus, struct pollfd *pollfds)
{
    int count = 0;
    Word_t index = 0;
    DBusWatch** pwatch;

    JLF(pwatch, dbus->watches, index);
    while(pwatch != NULL) {
        DBusWatch* watch = *pwatch;

        if(dbus_watch_get_enabled(watch)) {
            pollfds[count].fd = dbus_watch_get_unix_fd(watch);
            pollfds[count].events = 0;

            int flags = dbus_watch_get_flags(watch);
            if(flags & DBUS_WATCH_READABLE) pollfds[count].events |= POLLIN | POLLPRI;
            if(flags & DBUS_WATCH_WRITABLE) pollfds[count].events |= POLLOUT;

            count += 1;
        }

        JLN(pwatch, dbus->watches, index);
    }

    return count;
}

int dbus_update(struct dbus* dbus)
{
    DBusDispatchStatus status;

    // handle watches
    Word_t watch_count = 0;
    JLC(watch_count, dbus->watches, 0, -1);
    struct pollfd* pollfds = (struct pollfd*)alloca(sizeof(struct pollfd) * watch_count);
    int fdcount = get_pollfds(dbus, pollfds);

    if(poll(pollfds, fdcount, 0) < 0) {
        return -1;
    }

    // process the watches
    DBusWatch** pwatch;
    Word_t index = 0;
    int c = 0;
    JLF(pwatch, dbus->watches, index);
    while(pwatch != NULL) {
        struct pollfd* poll_result = &pollfds[c];
        struct DBusWatch* watch = *pwatch;

        if(dbus_watch_get_enabled(watch)) {
            assert(poll_result->fd == dbus_watch_get_unix_fd(watch));

            int flags = 0;
            int revents = poll_result->revents;

            if((revents & POLLIN) != 0) flags |= DBUS_WATCH_READABLE;
            if((revents & POLLOUT) != 0) flags |= DBUS_WATCH_WRITABLE;
            if((revents & POLLERR) != 0) flags |= DBUS_WATCH_ERROR;
            if((revents & POLLHUP) != 0) flags |= DBUS_WATCH_HANGUP;

            if(flags != 0) dbus_watch_handle(watch, flags);

            c++;
        }
        JLN(pwatch, dbus->watches, index);
    }

    // dispatch incoming messages
    while((status = dbus_connection_get_dispatch_status(dbus->conn)) != DBUS_DISPATCH_COMPLETE) {
        dbus_connection_dispatch(dbus->conn);
    }

    // Send outgoing messages
    if(dbus_connection_has_messages_to_send(dbus->conn)) {
        dbus_connection_flush(dbus->conn);
    }

    return 0;
}

void dbus_block_connected(struct dbus* dbus, unsigned char* block_hash, size_t height, size_t ntx)
{
    dbus_uint32_t serial = (dbus_uint32_t)dbus->next_block_connected_signal_id;
    dbus->next_block_connected_signal_id += 1;

    DBusMessage* msg;
    DBusMessageIter args;
     
    msg = dbus_message_new_signal("/org/sarcharsoftware/chaind", "org.sarcharsoftware.chaind", "BlockConnected");
    if(msg == NULL) {
        log_warning("error in dbus_message_new_signal");
        return;
    }

    dbus_message_iter_init_append(msg, &args);

    char* block_hash_string = (char*)alloca(sizeof(char) * 65);
    __bytes_to_hexstring(block_hash, 32, block_hash_string, 64, 1);
    block_hash_string[64] = 0;

    size_t path_size = strlen(DBUS_BLOCK_PATH) + 1 + 64 + 1;
    char* path = (char *)alloca(sizeof(char) * path_size);
    sprintf(path, "%s/%s", DBUS_BLOCK_PATH, block_hash_string);
    path[path_size - 1] = 0;
 
    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, (void*)&path)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return;
    }

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, (void*)&block_hash_string)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return;
    }

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, (void*)&height)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return;
    }

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, (void*)&ntx)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return;
    }
     
    if(!dbus_connection_send(dbus->conn, msg, &serial)) {
        log_warning("error in dbus_connection_send");
        dbus_message_unref(msg);
        return;
    }

    // we specifically don't call flush() here, and let it get called in update()
    dbus_message_unref(msg);
}

static DBusHandlerResult handle_chaind_introspection(DBusConnection *conn, DBusMessage *msg, void *userdata)
{
    DBusMessage* response = dbus_message_new_method_return(msg);
    if(response == NULL) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    DBusMessageIter args;
    dbus_message_iter_init_append(response, &args);

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &_introspection_chaind_xml)) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if(!dbus_connection_send(conn, response, NULL)) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    dbus_connection_flush(conn);
    dbus_message_unref(response);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_chaind_get_block(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    char const* hash_string = NULL;
    if(!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &hash_string, DBUS_TYPE_INVALID)) {
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if(strlen(hash_string) != 64 || !is_hex_string(hash_string, 64)) {
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    size_t path_size = strlen(DBUS_BLOCK_PATH) + 1 + 64 + 1;
    char* path = (char *)alloca(sizeof(char) * path_size);
    sprintf(path, "%s/%s", DBUS_BLOCK_PATH, hash_string);
    path[path_size - 1] = 0;

    DBusMessage* response = dbus_message_new_method_return(msg);
    if(response == NULL) return DBUS_HANDLER_RESULT_NEED_MEMORY;

    if(!dbus_message_append_args(response, DBUS_TYPE_OBJECT_PATH, (void*)&path, DBUS_TYPE_INVALID)) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if(!dbus_connection_send(conn, response, NULL)) return DBUS_HANDLER_RESULT_NEED_MEMORY;
    dbus_connection_flush(conn);
    dbus_message_unref(response);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_chaind_get_best_block(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    struct dbus* dbus = (struct dbus*)userdata;
    struct blockchain_link* link = chaind_best_blockchain_link(dbus->state);
    dbus_uint32_t height = (dbus_uint32_t)blockchain_link_height(link);

    unsigned char block_hash[32];
    block_header_hash(blockchain_link_block_header(link), block_hash);

    char * block_hash_string = (char*)alloca(sizeof(char) * 65);
    __bytes_to_hexstring(block_hash, 32, block_hash_string, 64, 1);
    block_hash_string[64] = 0;

    size_t path_size = strlen(DBUS_BLOCK_PATH) + 1 + 64 + 1;
    char* path = (char *)alloca(sizeof(char) * path_size);
    sprintf(path, "%s/%s", DBUS_BLOCK_PATH, block_hash_string);
    path[path_size - 1] = 0;

    DBusMessage* response = dbus_message_new_method_return(msg);
    if(response == NULL) return DBUS_HANDLER_RESULT_NEED_MEMORY;

    DBusMessageIter args;
    dbus_message_iter_init_append(response, &args);

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, (void*)&path)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, (void*)&block_hash_string)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, (void*)&height)) {
        log_warning("error in dbus_message_iter_append_basic");
        dbus_message_unref(msg);
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
 
    if(!dbus_connection_send(conn, response, NULL)) {
        log_warning("error in dbus_connection_send");
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    dbus_connection_flush(conn);
    dbus_message_unref(response);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_chaind_get_transaction(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult handle_chaind_message(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    const char *interface = dbus_message_get_interface(msg);
    const char *method    = dbus_message_get_member(msg);

    if(interface != NULL) printf("dbus interface: %s\n", interface);
    if(method != NULL) printf("dbus method: %s\n", method);

    if(strcmp(interface, DBUS_INTERFACE_INTROSPECTABLE) == 0) {
        return handle_chaind_introspection(conn, msg, userdata);
    } else if(strcmp(interface, "org.sarcharsoftware.chaind") == 0 && method != NULL) {
        if(strcmp(method, "GetBlock") == 0) {
            return handle_chaind_get_block(conn, msg, userdata);
        } else if(strcmp(method, "GetBestBlock") == 0) {
            return handle_chaind_get_best_block(conn, msg, userdata);
        } else if(strcmp(method, "GetTransaction") == 0) {
            return handle_chaind_get_transaction(conn, msg, userdata);
        }
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult filter_message(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    //const char *interface = dbus_message_get_interface(msg);
    //const char *method    = dbus_message_get_member(msg);
    const char *object    = dbus_message_get_path(msg);

    //if(interface != NULL) printf("dbus interface: %s\n", interface);
    //if(method != NULL) printf("dbus method: %s\n", method);
    //if(object != NULL) printf("dbus object: %s\n", object);

    if(object != NULL 
     && strlen(object) == (strlen(DBUS_BLOCK_PATH) + 1 + 64) 
     && strncmp(DBUS_BLOCK_PATH, object, strlen(DBUS_BLOCK_PATH)) == 0 
     && object[strlen(DBUS_BLOCK_PATH)] == '/'
     && is_hex_string(&object[strlen(DBUS_BLOCK_PATH)+1], 64)) {
        return dbus_block_filter_message(conn, msg, userdata, &object[strlen(DBUS_BLOCK_PATH)+1]);
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

