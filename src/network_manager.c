#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Judy.h>
#include <libchain/libchain.h>

#include "chaind.h"
#include "config.h"
#include "database.h"
#include "memory_pool.h"
#include "network_manager.h"
#include "network_peer.h"

struct network_manager {
    struct chaind* chaind;

    struct peer_discovery* peer_discovery;

    int num_peers;
    int num_peer_goal;
    int next_peer_id;
    void* peer_list;
    void* peer_by_address;

    vector poll_fds;
    void* poll_socket_by_peer;
    fd_set poll_read_fds;
    fd_set poll_write_fds;
    fd_set poll_exception_fds;
    int poll_max_fd;

    void* wanted_invs_by_inv;
    void* block_inv_list;
    void* tx_inv_list;
    Word_t tail_block_inv_id;
    Word_t head_block_inv_id;
    Word_t tail_tx_inv_id;
    Word_t head_tx_inv_id;
    void* claimed_invs;

    int* listening_sockets;
};

static void remove_from_wanted_invs(struct network_manager*, struct inv const*, size_t num_invs);

static int start_peer(struct network_manager* nm)
{
    // Randomly pick an address to connect to
    struct network_address address;
    int have_address = 0;

    for(int i = 0; i < 50; i++) {
        if(database_get_random_peer_address(chaind_database(nm->chaind), &address) <= 0) {
            // Error, or no address to select
            break;
        }

        // Apply default port if sin_port == 0
        if(address.sin_port == 0) address.sin_port = htons(NETWORK_DEFAULT_PORT);

        if(network_manager_get_peer_by_address(nm, &address) == NULL) {
            have_address = 1;
            break;
        }
    }

    if(!have_address) return -1;

    struct network_peer* peer = network_peer_create(nm);
    struct network_peer** ppeer = NULL;

    Word_t peer_id = nm->next_peer_id;
    JLI(ppeer, nm->peer_list, peer_id);
    *ppeer = peer;
    nm->next_peer_id += 1;

    Word_t* pindex;
    JHSI(pindex, nm->peer_by_address, (uint8_t*)&address, sizeof(struct network_address));
    *pindex = peer_id;

    int res = network_peer_connect(peer, &address, blockchain_link_height(chaind_best_blockchain_link(nm->chaind)));

    if(res != 0) {
        int rc;
        JLD(rc, nm->peer_list, peer_id);
        JHSD(rc, nm->peer_by_address, (uint8_t*)&address, sizeof(struct network_address));
        network_peer_destroy(peer);
        return res;
    }

    nm->num_peers += 1;
    return 0;
}

static void stop_peer(struct network_manager* nm, struct network_peer* peer)
{
    struct network_address address;
    network_peer_address(peer, &address);

    Word_t* pindex;
    JHSG(pindex, nm->peer_by_address, (uint8_t*)&address, sizeof(struct network_address));
    assert(pindex != NULL);

    Word_t peer_id = *pindex;
    struct network_peer** ppeer;
    JLG(ppeer, nm->peer_list, peer_id);
    assert(ppeer != NULL);
    assert(*ppeer == peer);

    // Remove from lists
    int rc;
    JLD(rc, nm->peer_list, peer_id);
    JHSD(rc, nm->peer_by_address, (uint8_t*)&address, sizeof(struct network_address));
    
    // Done with you!
    network_peer_destroy(peer);
    nm->num_peers -= 1;
}

struct network_manager* network_manager_create(struct chaind* chaind)
{
    struct network_manager* nm = (struct network_manager*)malloc(sizeof(struct network_manager));
    zero(nm);

    nm->chaind = chaind;

    nm->peer_list = NULL;
    nm->peer_by_address = NULL;
    nm->next_peer_id = 0;

    nm->num_peers = 0;
    nm->num_peer_goal = 8;
    nm->peer_discovery = NULL;

    vector_init(&nm->poll_fds);
    nm->poll_socket_by_peer = NULL;
    FD_ZERO(&nm->poll_read_fds);
    FD_ZERO(&nm->poll_write_fds);
    FD_ZERO(&nm->poll_exception_fds);
    nm->poll_max_fd = 0;

    nm->wanted_invs_by_inv = NULL;
    nm->block_inv_list = NULL;
    nm->tail_block_inv_id = 0;
    nm->head_block_inv_id = 0;
    nm->tx_inv_list = NULL;
    nm->tail_tx_inv_id = 0;
    nm->head_tx_inv_id = 0;
    nm->claimed_invs = NULL;

    return (struct network_manager*)nm;
}

static void check_peer_discovery(struct network_manager* nm)
{
    if(nm->peer_discovery != NULL) {
        int r = 0;
        struct network_address address;

        while((r = peer_discovery_get(nm->peer_discovery, &address)) > 0) {
            database_add_peer_address(chaind_database(nm->chaind), &address);
        }

        if(r < 0) {
            peer_discovery_done(nm->peer_discovery);
            nm->peer_discovery = NULL;
        }
    } else {
        if((nm->num_peers < nm->num_peer_goal) && (database_has_peer_addresses(chaind_database(nm->chaind)) == 0)) {
            nm->peer_discovery = peer_discovery_start();
        }
    }
}

static void update_peers(struct network_manager* nm)
{
    // Perform the select first
    fd_set read_fds      = nm->poll_read_fds,
           write_fds     = nm->poll_write_fds,
           exception_fds = nm->poll_exception_fds;

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    if(select(nm->poll_max_fd + 1, &read_fds, &write_fds, &exception_fds, &timeout) < 0) {
        // weird error?
        perror("select");
        return;
    }

    // Then loop over all peers passing in the select status
    struct network_peer** ppeer = NULL;
    Word_t index = 0;

    struct vector disconnected_peers;
    vector_init(&disconnected_peers);

    JLF(ppeer, nm->peer_list, index);
    while(ppeer != NULL) {
        int action_flags = 0;

        int* psock = NULL;
        uintptr_t p = (uintptr_t)*ppeer;
        JLG(psock, nm->poll_socket_by_peer, p);
        if(psock != NULL) {
            if(FD_ISSET(*psock, &read_fds)) action_flags |= NETWORK_PEER_ACTION_FLAGS_READ;
            if(FD_ISSET(*psock, &write_fds)) action_flags |= NETWORK_PEER_ACTION_FLAGS_WRITE;
            if(FD_ISSET(*psock, &exception_fds)) action_flags |= NETWORK_PEER_ACTION_FLAGS_EXCEPTION;
        }

        network_peer_update(*ppeer, action_flags);

        if(network_peer_disconnected(*ppeer) == 1) {
            vector_add(&disconnected_peers, (uintptr_t)*ppeer);
        }

        JLN(ppeer, nm->peer_list, index);
    }

    size_t num_disconnected = vector_count(&disconnected_peers);
    for(size_t i = 0; i < num_disconnected; i++) {
        struct network_peer* peer = (struct network_peer*)vector_get(&disconnected_peers, i);
        stop_peer(nm, peer);
    }

    vector_free(&disconnected_peers);
}

int network_manager_listen(struct network_manager* nm)
{
    struct config* cfg = chaind_config(nm->chaind);

    size_t num_interfaces = cfg->network.num_interfaces;
    nm->listening_sockets = (int*)malloc(sizeof(int) * cfg->network.num_interfaces);

    for(size_t i = 0; i < num_interfaces; i++) {
        struct network_address* interface = &cfg->network.interfaces[i];
        if(interface->type == NETWORK_ADDRESS_TYPE_IPV4) {
            nm->listening_sockets[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if(nm->listening_sockets[i] < 0) {
                return -1;
            }

            struct sockaddr_in bind_addr;
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr = interface->ipv4.addr;
            bind_addr.sin_port = interface->sin_port != 0 ? interface->sin_port : NETWORK_DEFAULT_PORT;

            if(bind(nm->listening_sockets[i], (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
                close(nm->listening_sockets[i]);
                return -1;
            }
    
            int flags = fcntl(nm->listening_sockets[i], F_GETFL, 0);
            if (flags < 0) {
                close(nm->listening_sockets[i]);
                return -1;
            }
    
            flags |= O_NONBLOCK;
            if(fcntl(nm->listening_sockets[i], F_SETFL, flags) != 0) {
                close(nm->listening_sockets[i]);
                return -1;
            }
    
            listen(nm->listening_sockets[i], 10);
        } else {
            assert(0); // TODO
        }
    }

    return 0;
}

int network_manager_update(struct network_manager* nm)
{
    // If disabled, do nothing
    if(chaind_config(nm->chaind)->network.participate != 1) {
        return 0;
    }

    check_peer_discovery(nm);

    // If we have fewer peers connected than we want, try connecting some
    while(nm->num_peers < nm->num_peer_goal) {
        if(start_peer(nm) < 0) {
            // This can happen if we're out of addresses
            break;
        }
    }

    update_peers(nm);

    return 0;
}

int network_manager_destroy(struct network_manager* nm)
{
    if(nm->listening_sockets != NULL) {
        size_t num_interfaces = chaind_config(nm->chaind)->network.num_interfaces;
        for(size_t i = 0; i < num_interfaces; i++) {
            close(nm->listening_sockets[i]);
        }
        free(nm->listening_sockets);
    }

    int rc;
    Word_t wrc;

    JHSFA(wrc, nm->claimed_invs);
    JHSFA(wrc, nm->wanted_invs_by_inv);

    struct inv** pinv = NULL;
    Word_t index = 0;
    JLF(pinv, nm->block_inv_list, index);
    while(pinv != NULL) {
        free(*pinv);
        JLN(pinv, nm->block_inv_list, index);
    }

    JLFA(wrc, nm->block_inv_list);

    index = 0;
    JLF(pinv, nm->tx_inv_list, index);
    while(pinv != NULL) {
        free(*pinv);
        JLN(pinv, nm->tx_inv_list, index);
    }

    JLFA(wrc, nm->tx_inv_list);

    if(nm->peer_discovery != NULL) {
        peer_discovery_done(nm->peer_discovery);
        nm->peer_discovery = NULL;
    }

    JLFA(rc, nm->poll_socket_by_peer);
    vector_free(&nm->poll_fds);

    // TODO free nm->peer_list
    // TODO free nm->peer_by_address
    free(nm);
    return 0;
}

struct network_peer* network_manager_get_peer_by_address(struct network_manager* nm, struct network_address* address)
{
    Word_t* pindex;
    JHSG(pindex, nm->peer_by_address, (uint8_t*)address, sizeof(struct network_address));
    if(pindex == NULL) return NULL;

    Word_t peer_id = *pindex;
    struct network_peer** ppeer;
    JLG(ppeer, nm->peer_list, peer_id);
    if(ppeer == NULL) return NULL;

    return *ppeer;
}

int network_manager_register_peer_for_polling(struct network_manager* nm, int sock, struct network_peer* peer)
{
    uintptr_t p = (uintptr_t)peer; 
    int* psock = NULL;
    JLG(psock, nm->poll_socket_by_peer, p);
    assert(psock == NULL); // duplicate insert

    JLI(psock, nm->poll_socket_by_peer, p);
    if(psock == NULL) { // memory failure
        return -1;
    }

    *psock = sock;

    FD_SET(sock, &nm->poll_read_fds);
    FD_SET(sock, &nm->poll_write_fds);
    FD_SET(sock, &nm->poll_exception_fds);

    vector_add(&nm->poll_fds, (uintptr_t)sock);
    if(sock > nm->poll_max_fd) nm->poll_max_fd = sock;

    return 0;
}

static int compint(const void* a, const void* b)
{
    int ai = (int)(*((uintptr_t*)a) & 0xFFFFFFFF);
    int bi = (int)(*((uintptr_t*)b) & 0xFFFFFFFF);
    if(ai < bi) return -1;
    if(ai > bi) return  1;
    return 0;
}

int network_manager_unregister_peer_for_polling(struct network_manager* nm, struct network_peer* peer)
{
    uintptr_t p = (uintptr_t)peer; 
    int* psock = NULL;
    int sock;

    JLG(psock, nm->poll_socket_by_peer, p);
    if(psock == NULL) return -1; // doesn't exist
    sock = *psock;

    int rc;
    JLD(rc, nm->poll_socket_by_peer, p);

    FD_CLR(sock, &nm->poll_read_fds);
    FD_CLR(sock, &nm->poll_write_fds);
    FD_CLR(sock, &nm->poll_exception_fds);

    if(sock == nm->poll_max_fd) {
        size_t num_fds = vector_count(&nm->poll_fds);

        // Need to figure out what the previous max fd was, which means..
        qsort(vector_data(&nm->poll_fds), (size_t)num_fds, sizeof(uintptr_t), compint);
        int old_fd = (int)vector_pop(&nm->poll_fds);
        assert(old_fd == sock);

        nm->poll_max_fd = 0;
        if(num_fds > 1) {
            nm->poll_max_fd = vector_get(&nm->poll_fds, num_fds - 2);
        }
    }

    return 0;
}

void network_manager_handle_inv(struct network_manager* nm, struct network_peer* peer, struct inv const* inv)
{
    // Determine if we know about this item and if so, ignore it
    bytes_to_hexstring(inv->hash, INV_HASH_SIZE, s, 1);
    printf("got inv %s %s", inv->type == INV_TYPE_TX ? "tx" : "block", s);

    // Check if it's in mempool
    struct memory_pool* memory_pool = chaind_memory_pool(nm->chaind);
    if(memory_pool_has_inv(memory_pool, inv)) {
        printf(" (mempool)\n");
        return;
    }

    // Check the list of invs we care about. We include the inv->type field
    // in the index in case a block and tx have the same hash, despite it 
    // being astronomically unlikely.
    Word_t* pindex = NULL;
    JHSG(pindex, nm->wanted_invs_by_inv, (uint8_t*)inv, sizeof(struct inv));
    if(pindex != NULL) {
        printf(" (invpool)\n");
        return;
    }

    // Check if it's in the database
    struct database* database = chaind_database(nm->chaind);
    if(database_has_inv(database, inv) != 0) {
        printf(" (db)\n");
        return;
    }

    // We don't know this inv, so we take note in the appropriate list
    struct inv* ninv = (struct inv*)malloc(sizeof(struct inv));
    memcpy(ninv, inv, sizeof(struct inv));

    // Add to the list of items we need to get
    Word_t index = 0;
    struct inv** pinv = NULL;

    switch(inv->type) {
    case INV_TYPE_BLOCK:
        index = nm->head_block_inv_id;
        JLI(pinv, nm->block_inv_list, index);
        assert(pinv != NULL);
        *pinv = ninv;
        nm->head_block_inv_id += 1;
        break;
    case INV_TYPE_TX:
        index = nm->head_tx_inv_id;
        JLI(pinv, nm->tx_inv_list, index);
        assert(pinv != NULL);
        *pinv = ninv;
        nm->head_tx_inv_id += 1;
        break;
    case INV_TYPE_ERROR:
        // TODO 
        break;
    }

    if(inv->type != INV_TYPE_ERROR) {
        JHSI(pindex, nm->wanted_invs_by_inv, (uint8_t*)inv, sizeof(struct inv));
        assert(pindex != NULL);
        *pindex = index;
    }

    printf("\n");
}

static void remove_from_wanted_invs(struct network_manager* nm, struct inv const* invs, size_t num_invs)
{
    Word_t swap_index;
    struct inv** pinv1;
    struct inv** pinv2;
    struct inv* inv2;
    int rc;
    Word_t* pindex1;
    Word_t* pindex2;

    for(size_t i = 0; i < num_invs; i++) {
        struct inv const* inv = &invs[i];

        JHSG(pindex1, nm->wanted_invs_by_inv, (uint8_t*)inv, sizeof(struct inv));
        assert(pindex1 != NULL);

        Word_t* tail = NULL;
        Word_t* head = NULL;
        void** list = NULL;

        switch(inv->type) {
        case INV_TYPE_BLOCK:
            head = &nm->head_block_inv_id;
            tail = &nm->tail_block_inv_id;
            list = &nm->block_inv_list;
            break;
        case INV_TYPE_TX:
            head = &nm->head_tx_inv_id;
            tail = &nm->tail_tx_inv_id;
            list = &nm->tx_inv_list;
            break;
        case INV_TYPE_ERROR:
            assert(0);
            break;
        }

        assert(*head > *tail);

        swap_index = *head - 1;
        if(*pindex1 == *tail) {
            JLG(pinv1, *list, *pindex1);
            assert(memcmp(*pinv1, inv, sizeof(struct inv)) == 0);

            free(*pinv1);
            JLD(rc, *list, *pindex1);

            (*tail) += 1;
        } else if(*pindex1 < swap_index) {
            JLG(pinv1, *list, *pindex1);
            assert(pinv1 != NULL);

            JLG(pinv2, *list, swap_index);
            assert(pinv2 != NULL);

            assert(memcmp(*pinv1, inv, sizeof(struct inv)) == 0);
            assert(memcmp(*pinv1, *pinv2, sizeof(struct inv)) != 0);

            // JLD will kill the pinv2 pointer, so save the inv
            inv2 = *pinv2;
            free(*pinv1);
            JLD(rc, *list, swap_index);

            // JLD can reorder the array..
            JLI(pinv1, *list, *pindex1);
            *pinv1 = inv2;

            // Remove from wanted array
            JHSG(pindex2, nm->wanted_invs_by_inv, (uint8_t*)inv2, sizeof(struct inv));
            *pindex2 = *pindex1;
            (*head) -= 1;
        } else {
            assert(*pindex1 == swap_index);

            JLG(pinv2, *list, swap_index);
            assert(memcmp(*pinv2, inv, sizeof(struct inv)) == 0);

            free(*pinv2);
            JLD(rc, *list, swap_index);

            (*head) -= 1;
        }

        JHSD(rc, nm->wanted_invs_by_inv, (uint8_t*)inv, sizeof(struct inv));
    }
}

size_t network_manager_get_invs(struct network_manager* nm, enum INV_TYPE invtype, struct inv* out, size_t num_invs, int skip_claimed)
{
    size_t r = 0;
    assert(invtype != INV_TYPE_ERROR);

    Word_t start_index = 0;
    Word_t last_index = -1;
    void* list = NULL;

    switch(invtype) {
    case INV_TYPE_TX:
        start_index = nm->tail_tx_inv_id;
        last_index = nm->head_tx_inv_id;
        list = nm->tx_inv_list;
        break;
    case INV_TYPE_BLOCK:
        start_index = nm->tail_block_inv_id;
        last_index = nm->head_block_inv_id;
        list = nm->block_inv_list;
        break;
    case INV_TYPE_ERROR:
        assert(0);
        return 0;
    }

    for(Word_t index = start_index; index < last_index && r < num_invs; index++) {
        struct inv** pinv = NULL;
        JLG(pinv, list, index);
        assert(pinv != NULL);

        // check if this inv is claimed by a peer
        if(skip_claimed != 0) {
            Word_t* pindex = NULL;
            JHSG(pindex, nm->claimed_invs, (uint8_t*)(*pinv), sizeof(struct inv));
            if(pindex != NULL) {
                // This inv is claimed
                continue;
            }
        }

        memcpy(&out[r], *pinv, sizeof(struct inv));
        r++;
    }

    return r;
}

int network_manager_claim_invs(struct network_manager* nm, struct network_peer* peer, struct inv const* invs, size_t num_invs)
{
    // Only returns 0 (success) if all invs can be claimed
    int all_good = 1;

    for(size_t i = 0; i < num_invs; i++) {
        Word_t* pindex = NULL;
        JHSG(pindex, nm->claimed_invs, (uint8_t*)(&invs[i]), sizeof(struct inv));
        if(pindex != NULL) {
            // This inv is claimed already
            all_good = 0;
            break;
        }
    }

    if(all_good == 0) return -1;

    // Mark all invs as claimed
    for(size_t i = 0; i < num_invs; i++) {
        Word_t* pindex = NULL;
        JHSI(pindex, nm->claimed_invs, (uint8_t*)(&invs[i]), sizeof(struct inv));
        assert(pindex != NULL);
        *pindex = 1;
    }

    return 0;
}

void network_manager_unclaim_invs(struct network_manager* nm, struct network_peer* peer, struct inv const* invs, size_t num_invs)
{
    int rc;
    int stopped = 0;

    for(size_t i = 0; i < num_invs; i++) {
        JHSD(rc, nm->claimed_invs, (uint8_t*)(&invs[i]), sizeof(struct inv));
        if(rc == 0 && stopped == 0) {
            network_peer_disconnect(peer, "bad unclaim");
            stopped = 1;
        }
    }
}

struct block_locator* network_manager_block_locator(struct network_manager* nm)
{
    return blockchain_link_block_locator(chaind_best_blockchain_link(nm->chaind));
}

int network_manager_should_send_getblocks(struct network_manager* nm, struct network_peer* peer, size_t peer_height)
{
    // TODO check if any peer has requested blocks, check timeout on getblocks, etc
    return ((nm->head_block_inv_id == nm->tail_block_inv_id) && blockchain_link_height(chaind_best_blockchain_link(nm->chaind)) < peer_height) ? 1 : 0;
}

void network_manager_handle_addr(struct network_manager* nm, struct network_peer* peer, struct network_address* address, uint64_t services, unsigned int timestamp)
{
    database_add_peer_address(chaind_database(nm->chaind), address);
}

void network_manager_handle_block(struct network_manager* nm, struct network_peer* peer, struct inv const* inv, struct block* block)
{
    // Remove from claimed list
    network_manager_unclaim_invs(nm, peer, inv, 1);

    // Remove from inv set so other nodes don't request it
    remove_from_wanted_invs(nm, inv, 1);

    // Pass it up
    if(chaind_handle_block(nm->chaind, inv, block) != 0) {
        network_peer_disconnect(peer, "invalid block");
    }

    block_free(block);
}

void network_manager_handle_tx(struct network_manager* nm, struct network_peer* peer, struct inv const* inv, struct transaction* tx)
{
    // Remove from claimed list
    network_manager_unclaim_invs(nm, peer, inv, 1);

    // Remove from inv set so other nodes don't request it
    remove_from_wanted_invs(nm, inv, 1);

    // Pass it up
    if(chaind_handle_tx(nm->chaind, inv, tx) != 0) {
        network_peer_disconnect(peer, "invalid tx");
    }

    transaction_free(tx);
}


