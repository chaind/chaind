#ifndef __NETWORK_H
#define __NETWORK_H

#include <netdb.h>

enum NETWORK_ADDRESS_TYPE {
    NETWORK_ADDRESS_TYPE_IPV4,
    NETWORK_ADDRESS_TYPE_IPV6
};

struct network_address {
    enum NETWORK_ADDRESS_TYPE type;

    union {
        struct {
            struct in_addr addr;
        } ipv4;
        struct {
            struct in6_addr addr;
        } ipv6;
    };

    unsigned short sin_port;
};

#endif
