#ifndef __CONFIG_H
#define __CONFIG_H

struct config_impl;
struct network_address;

struct config {
    struct config_impl* impl;

    struct {
        char const* hostname;
        int port;
        char const* database;
    } mongodb;

    struct {
        int level;
    } logging;

    struct {
        int participate;

        size_t num_interfaces;
        struct network_address* interfaces;
    } network;
};

struct config* config_load(char const*);
void config_free(struct config*);

#endif /* __CONFIG_H */
