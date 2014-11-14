#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <libchain/libchain.h>
#include <libconfig.h>

#include "config.h"
#include "network_manager.h"

struct config_impl {
    config_t libconfig_data;
};

static int parse_network_address(struct network_address* out, char const* str, int default_port)
{
    char buffer[16] = { 0, };
    char* c = strchr(str, ':');
    
    if(c == NULL) {
        strcpy(buffer, str);
        out->sin_port = htonl(default_port);
    } else {
        memcpy(buffer, str, (uintptr_t)c - (uintptr_t)str);
        if(strlen(c) < 2) {
            out->sin_port = htonl(default_port);
        } else {
            out->sin_port = htonl(atoi(c + 1));
        }
    }

    inet_aton(buffer, &out->ipv4.addr);
    out->type = NETWORK_ADDRESS_TYPE_IPV4;
    return 1;
}

static int parse_network_address6(struct network_address* out, char const* str, int default_port)
{
    // TODO
    assert(0);
    out->type = NETWORK_ADDRESS_TYPE_IPV6;
    return 1;
}

struct config* config_load(char const* filename)
{
    struct config* cfg = (struct config*)malloc(sizeof(struct config));
    zero(cfg);

    cfg->impl = (struct config_impl*)malloc(sizeof(struct config_impl));
    zero(cfg->impl);

    if(config_read_file(&cfg->impl->libconfig_data, filename) != CONFIG_TRUE) {
        char const* errorfile = config_error_file(&cfg->impl->libconfig_data);
        if(errorfile == NULL) errorfile = filename;
        fprintf(stderr, "error: cannot read %s: %s (line %d)\n", 
                errorfile,
                config_error_text(&cfg->impl->libconfig_data),
                config_error_line(&cfg->impl->libconfig_data));
        goto error;
    }

#define GET_REQUIRED_STRING(path, storage) \
    if(config_lookup_string(&cfg->impl->libconfig_data, path, &(storage)) != CONFIG_TRUE) { \
        fprintf(stderr, "error: required configuration string \"%s\" not found\n", path); \
        goto error; \
    }

#define GET_REQUIRED_INT(path, storage) \
    if(config_lookup_int(&cfg->impl->libconfig_data, path, &(storage)) != CONFIG_TRUE) { \
        fprintf(stderr, "error: required configuration value \"%s\" not found\n", path); \
        goto error; \
    }

#define GET_STRING(path, storage, default_value) \
    if(config_lookup_string(&cfg->impl->libconfig_data, path, &(storage)) != CONFIG_TRUE) { \
        storage = default_value; \
    }

#define GET_INT(path, storage, default_value) \
    if(config_lookup_int(&cfg->impl->libconfig_data, path, &(storage)) != CONFIG_TRUE) { \
        storage = default_value; \
    }

#define GET_BOOL(path, storage, default_value) \
    if(config_lookup_bool(&cfg->impl->libconfig_data, path, &(storage)) != CONFIG_TRUE) { \
        storage = default_value; \
    }
    
    GET_REQUIRED_STRING("mongodb.hostname", cfg->mongodb.hostname);
    GET_INT("mongodb.port", cfg->mongodb.port, 27017);
    GET_REQUIRED_STRING("mongodb.database", cfg->mongodb.database);

    char const* logging_level = NULL;
    GET_STRING("logging.level", logging_level, "info");

    GET_BOOL("network.participate", cfg->network.participate, 1);

    config_setting_t* interfaces = config_lookup(&cfg->impl->libconfig_data, "network.interfaces");
    int num_interfaces = config_setting_length(interfaces);

    config_setting_t* interfaces6 = config_lookup(&cfg->impl->libconfig_data, "network.interfaces6");
    int num_interfaces6 = config_setting_length(interfaces6);

    cfg->network.interfaces = (struct network_address*)malloc(sizeof(struct network_address) * (num_interfaces + num_interfaces6));
    cfg->network.num_interfaces = (size_t)(num_interfaces + num_interfaces6);

    size_t interface_index = 0;
    for(size_t i = 0; i < num_interfaces; i++, interface_index++) {
        char const* elem = config_setting_get_string_elem(interfaces, i);
        if(parse_network_address(&cfg->network.interfaces[interface_index], elem, NETWORK_DEFAULT_PORT) != 1) {
            fprintf(stderr, "error: could not parse interface \"%s\"\n", elem); \
            goto error;
        }
    }

    for(size_t i = 0; i < num_interfaces6; i++, interface_index++) {
        char const* elem = config_setting_get_string_elem(interfaces6, i);
        if(parse_network_address6(&cfg->network.interfaces[interface_index], elem, NETWORK_DEFAULT_PORT) != 1) {
            fprintf(stderr, "error: could not parse interface \"%s\"\n", elem); \
            goto error;
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    if(strcasecmp(logging_level, "emerg") == 0) cfg->logging.level = LOG_EMERG;
    else if(strcasecmp(logging_level, "alert") == 0) cfg->logging.level = LOG_ALERT;
    else if(strcasecmp(logging_level, "crit") == 0) cfg->logging.level = LOG_CRIT;
    else if(strcasecmp(logging_level, "err") == 0) cfg->logging.level = LOG_ERR;
    else if(strcasecmp(logging_level, "warning") == 0) cfg->logging.level = LOG_WARNING;
    else if(strcasecmp(logging_level, "notice") == 0) cfg->logging.level = LOG_NOTICE;
    else if(strcasecmp(logging_level, "info") == 0) cfg->logging.level = LOG_INFO;
    else if(strcasecmp(logging_level, "debug") == 0) cfg->logging.level = LOG_DEBUG;
    else {
        fprintf(stderr, "error: invalid string \"%s\" for logging.level\n", logging_level);
        goto error;
    }

    return cfg;
error:
    config_free(cfg);
    return NULL;
}

void config_free(struct config* cfg)
{
    if(cfg != NULL) {
        free(cfg->network.interfaces);
        if(cfg->impl != NULL) {
            config_destroy(&cfg->impl->libconfig_data);
            free(cfg->impl);
        }
        free(cfg);
    }
}

