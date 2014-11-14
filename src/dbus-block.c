#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include <libchain/libchain.h>
#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-block.h"
#include "logging.h"

#include "introspection/block.h"

char const* const DBUS_BLOCK_PATH = "/org/sarcharsoftware/chaind/blocks";
 
static DBusHandlerResult filter_block_introspectable_introspect(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    DBusMessage* response = dbus_message_new_method_return(msg);
    if(response == NULL) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    DBusMessageIter args;
    dbus_message_iter_init_append(response, &args);
 
    if(!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &_introspection_block_xml)) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    if(!dbus_connection_send(conn, response, NULL)) {
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }

    dbus_connection_flush(conn);
    dbus_message_unref(response);

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult filter_block_introspectable(DBusConnection* conn, DBusMessage* msg, void* userdata)
{
    if(dbus_message_is_method_call(msg, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
        return filter_block_introspectable_introspect(conn, msg, userdata);
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult filter_block_handle_serialize(DBusConnection* conn, DBusMessage* msg, void* userdata, char const* hash_string)
{
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult dbus_block_filter_message(DBusConnection* conn, DBusMessage* msg, void* userdata, char const* hash_string)
{
    const char *interface = dbus_message_get_interface(msg);
    const char *method    = dbus_message_get_member(msg);

    if(strcmp(interface, DBUS_INTERFACE_INTROSPECTABLE) == 0) {
        return filter_block_introspectable(conn, msg, userdata);
    } else if(strcmp(interface, "org.sarcharsoftware.chaind.block") == 0) {
        if(strcmp(method, "Serialize") == 0) {
            return filter_block_handle_serialize(conn, msg, userdata, hash_string);
        }
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

