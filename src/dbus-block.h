#ifndef __DBUS_BLOCK_H
#define __DBUS_BLOCK_H

#include <dbus/dbus.h>

DBusHandlerResult dbus_block_filter_message(DBusConnection* conn, DBusMessage* msg, void*, char const*);

extern char const* const DBUS_BLOCK_PATH;

#endif /* __DBUS_BLOCK_H */
