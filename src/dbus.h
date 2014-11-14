#ifndef __DBUS_H
#define __DBUS_H

struct dbus;

struct dbus* dbus_start_service();
void dbus_destroy_service(struct dbus*);
int dbus_update(struct dbus*);

void dbus_block_connected(struct dbus*, unsigned char*, size_t, size_t);

#endif /* __DBUS_H */
