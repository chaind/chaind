// TODO - ipv6 support
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <Judy.h>

#include "bitcoin.h"
#include "network.h"
#include "peer_discovery.h"
#include "util.h"

struct peer_discovery {
    pthread_t thread;
    pthread_mutex_t lock;
    void*     results;
    int       num_results;
    int       get_index;
    int       done;
};

static char const* const dns_seeds[] = {
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitnodes.io",
    "seeds.bitcoin.open-nodes.org",
    "bitseed.xf2.org"
};

static int const DNS_SEEDS_COUNT = sizeof(dns_seeds) / sizeof(dns_seeds[0]);

static void* discovery_thread(void* data)
{
    struct peer_discovery* p = (struct peer_discovery*)data;
    if(p == NULL) return NULL;

    struct addrinfo hint;
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_ADDRCONFIG;

    for(int i = 0; i < DNS_SEEDS_COUNT; i++) {
        struct addrinfo *res = NULL;
        int err = getaddrinfo(dns_seeds[i], NULL, &hint, &res);

        if(err != 0) {
            printf("[peer discovery] error: %s\n", gai_strerror(err));
            break;
        }

        while(res != NULL) {
            struct network_address* address = (struct network_address*)malloc(sizeof(struct network_address));
            address->sin_port = htons(BITCOIN_DEFAULT_PEER_PORT);

            if(res->ai_family == AF_INET) {
                address->type = NETWORK_ADDRESS_TYPE_IPV4;
                address->ipv4.addr = ((struct sockaddr_in*)(res->ai_addr))->sin_addr;
            } else if(res->ai_family == AF_INET6) {
                address->type = NETWORK_ADDRESS_TYPE_IPV6;
                address->ipv6.addr = ((struct sockaddr_in6*)(res->ai_addr))->sin6_addr;
            }

            err = pthread_mutex_lock(&p->lock);
            if(err != 0) {
                // Error locking?
                break;
            }

            Word_t index = p->num_results;
            struct network_address** paddress = NULL;
            JLI(paddress, p->results, index);

            if(paddress != NULL) {
                *paddress = address;
                p->num_results += 1;
            }

            pthread_mutex_unlock(&p->lock);

            if(paddress == NULL) {
                break;
            }

            res = res->ai_next;
        }

        freeaddrinfo(res);
    }

    p->done = 1;

    return NULL;
}

struct peer_discovery* peer_discovery_start()
{
    struct peer_discovery* r = (struct peer_discovery*)malloc(sizeof(struct peer_discovery));
    int ret;

    zero(r);
    r->num_results = 0;
    r->get_index = 0;
    r->results = NULL;
    r->done = 0;

    /* Create the mutex required to access results list */
    ret = pthread_mutex_init(&r->lock, NULL);
    if(ret != 0) {
        free(r);
        return NULL;
    }

    pthread_attr_t attr;
    ret = pthread_attr_init(&attr);
    if(ret != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return NULL;
    }

    /* Create the thread in a detached state, so that we don't have to call join */
    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(ret != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return NULL;
    }

    ret = pthread_create(&r->thread, NULL, discovery_thread, (void*)r);
    if(ret != 0) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return NULL;
    }

    return r;
}

int peer_discovery_get(struct peer_discovery* r, struct network_address* out)
{
    if(pthread_mutex_trylock(&r->lock) == 0) {
        pthread_mutex_unlock(&r->lock);

        Word_t index = (Word_t)r->get_index;
        struct network_address** pout = NULL;
        JLG(pout, r->results, index);
        if(pout != NULL) {
            *out = **pout;
            r->get_index += 1;
            return 1;
        }
    }

    if(r->done && r->get_index == r->num_results) return -1;
    return 0;
}

void peer_discovery_done(struct peer_discovery* r) 
{
    Word_t rc;
    Word_t index = 0;
    struct network_address** paddress;

    JLF(paddress, r->results, index);
    while(paddress != NULL) {
        free(*paddress);
        JLN(paddress, r->results, index);
    }

    JLFA(rc, r->results);
    pthread_mutex_destroy(&r->lock);
    free(r);
}
