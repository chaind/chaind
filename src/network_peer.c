#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <Judy.h>
#include <libchain/libchain.h>

#include "network_manager.h"
#include "network_peer.h"

#define CMD_HASH_ADDR     0xD67DFF7B
#define CMD_HASH_BLOCK    0x3518EC2F
#define CMD_HASH_INV      0x730A6C0F
#define CMD_HASH_NOTFOUND 0xCB77C4B8
#define CMD_HASH_TX       0x2109B25E
#define CMD_HASH_VERACK   0xBF639D6C
#define CMD_HASH_VERSION  0xD8C87B58

#define MESSAGE_MUST_COPY 0x01
#define MESSAGE_MUST_FREE 0x02
#define MESSAGE_MUST_SEND 0x04

#define READ_CHUNK_MAX_SIZE (16*1024)
#define PEER_TX_TIMEOUT 10
#define PEER_BLOCK_TIMEOUT 30
#define PEER_GETBLOCKS_TIMEOUT 10
#define TIME_BETWEEN_GETBLOCKS 10
#define CONNECT_TIMEOUT 5 

enum NETWORK_PEER_STATE {
    NETWORK_PEER_STATE_READY,
    NETWORK_PEER_STATE_CONNECTING,
    NETWORK_PEER_STATE_HANDSHAKING,
    NETWORK_PEER_STATE_CONNECTED,
    NETWORK_PEER_STATE_DISCONNECTED
};

struct network_peer {
    struct network_manager* nm;
    struct network_address address;
    enum NETWORK_PEER_STATE state;
    int socket;
    uint64_t connect_time;

    int current_height;

    Word_t read_chunk_next;
    Word_t read_chunk_last;
    void* read_chunks;
    size_t read_chunk_total;
    size_t total_read;

    Word_t message_queue_next;
    Word_t message_queue_last;
    void*  message_queue;
    size_t total_write;

    int sent_version;
    int received_version;
    int handshake_step;

    uint64_t nonce;
    unsigned int peer_version;
    uint64_t peer_services;
    uint64_t peer_time;
    uint64_t peer_nonce;
    char* peer_user_agent;
    unsigned int peer_height;
    unsigned char peer_full_relay;
    struct network_address my_address_from_peer;

    int getdata_block_waiting;
    uint64_t getdata_block_time;

    int getdata_tx_waiting;
    uint64_t getdata_tx_time;

    void* requested_invs;
    void* requested_invs_by_id;
    size_t next_requested_inv_id;

    unsigned int incoming_command;

    uint64_t getblocks_time;
    uint64_t last_getblocks_time;
};

struct read_chunk {
    size_t size;
    unsigned char data[READ_CHUNK_MAX_SIZE];
    unsigned char* head;
};

struct message {
    int flags;
    size_t size;
    unsigned char* data;
    unsigned char* head;
};

static void network_peer_reset(struct network_peer*);
int peer_printf(struct network_peer*, char const*, ...);

static void do_read(struct network_peer*);
static void do_write(struct network_peer*);
static void step(struct network_peer*);

static size_t read_chunks(struct network_peer*, unsigned char*, size_t, int);
static void process_read_chunks(struct network_peer*);
static void free_read_chunk(struct read_chunk*);
static void queue_message(struct network_peer*, unsigned char const*, size_t, int);
static void free_message(struct message*);

static void mark_invs_as_requested(struct network_peer*, struct inv const*, size_t);
static void remove_invs_from_requested(struct network_peer*, struct inv const*, size_t);

static void send_getblocks(struct network_peer*);
static void send_getdata(struct network_peer*, struct inv const*, size_t);
static void send_version(struct network_peer*);
static void send_verack(struct network_peer*);

static void handle_addr(struct network_peer*, unsigned char const*, size_t);
static void handle_block(struct network_peer*, unsigned char const*, size_t);
static void handle_inv(struct network_peer*, unsigned char const*, size_t);
static void handle_message(struct network_peer*, unsigned char const*, unsigned char const*, size_t);
static void handle_tx(struct network_peer*, unsigned char const*, size_t);
static void handle_version(struct network_peer*, unsigned char const*, size_t);
static void handle_verack(struct network_peer*, unsigned char const*, size_t);

struct network_peer* network_peer_create(struct network_manager* nm)
{
    struct network_peer* peer = (struct network_peer*)malloc(sizeof(struct network_peer));
    zero(peer);

    peer->nm = nm;

    peer->read_chunk_next = 0;
    peer->read_chunk_last = 0;
    peer->read_chunk_total = 0;
    peer->read_chunks = NULL;

    peer->message_queue_next = 0;
    peer->message_queue_last = 0;
    peer->message_queue = NULL;

    peer->peer_user_agent = NULL;

    peer->requested_invs = NULL;
    peer->requested_invs_by_id = NULL;
    peer->next_requested_inv_id = 0;

    peer->state = NETWORK_PEER_STATE_DISCONNECTED;
    network_peer_reset(peer);

    return (struct network_peer*)peer;
}

// Reset leaves a peer structure ready to connect/reconnect
static void network_peer_reset(struct network_peer* peer)
{
    network_peer_disconnect(peer, "reset");

    struct inv** pinv = NULL;
    Word_t index = 0;
    JLF(pinv, peer->requested_invs_by_id, index);
    while(pinv != NULL) {
        free(*pinv);
        JLN(pinv, peer->requested_invs_by_id, index);
    }

    int rc;
    JLFA(rc, peer->requested_invs_by_id);

    Word_t wrc;
    JHSFA(wrc, peer->requested_invs);

    // Clear the outgoing message_queue
    index = 0;
    struct message** pmsg;
    JLF(pmsg, peer->message_queue, index);
    while(pmsg != NULL) {
        JLD(rc, peer->message_queue, index);
        free_message(*pmsg);
        JLN(pmsg, peer->message_queue, index);
    }

    peer->message_queue_next = 0;
    peer->message_queue_last = 0;
    peer->total_write = 0;

    // Clear the incoming data
    index = 0;
    struct read_chunk** pchunk;
    JLF(pchunk, peer->read_chunks, index);
    while(pchunk != NULL) {
        JLD(rc, peer->read_chunks, index);
        free_read_chunk(*pchunk);
        JLN(pchunk, peer->read_chunks, index);
    }

    peer->read_chunk_next = 0;
    peer->read_chunk_last = 0;
    peer->read_chunk_total = 0;
    peer->total_read = 0;

    // Connection state
    peer->sent_version = 0;
    peer->received_version = 0;
    peer->handshake_step = 0;

    peer->peer_version = 0;
    peer->peer_services = 0;
    peer->peer_nonce = 0;
    peer->peer_height = 0;
    peer->peer_full_relay = 0;
    zero(&peer->my_address_from_peer);
    if(peer->peer_user_agent != NULL) {
        free(peer->peer_user_agent);
        peer->peer_user_agent = NULL;
    }

    peer->getdata_block_waiting = 0;
    peer->getdata_block_time = 0;
    peer->getdata_tx_waiting = 0;
    peer->getdata_tx_time = 0;

    peer->getblocks_time = 0;
    peer->last_getblocks_time = 0;

    peer->state = NETWORK_PEER_STATE_READY;
}

void network_peer_disconnect(struct network_peer* peer, char const* reason)
{
    struct inv** pinv = NULL;
    Word_t index = 0;

    switch(peer->state) {
    case NETWORK_PEER_STATE_CONNECTING:
    case NETWORK_PEER_STATE_HANDSHAKING:
    case NETWORK_PEER_STATE_CONNECTED:
        peer_printf(peer, "disconnecting: %s (%d sent/%d read)\n", reason, (int)peer->total_write, (int)peer->total_read);
        network_manager_unregister_peer_for_polling(peer->nm, peer);

        // Tell network manager to relinquish holds on any invs we have outstanding
        JLF(pinv, peer->requested_invs_by_id, index);
        while(pinv != NULL) {
            network_manager_unclaim_invs(peer->nm, peer, *pinv, 1);
            remove_invs_from_requested(peer, *pinv, 1);
            JLN(pinv, peer->requested_invs_by_id, index);
        }

        close(peer->socket);
        break;
    case NETWORK_PEER_STATE_READY:
    case NETWORK_PEER_STATE_DISCONNECTED:
        break;
    }

    peer->socket = -1;
    peer->state = NETWORK_PEER_STATE_DISCONNECTED;
}

int network_peer_disconnected(struct network_peer* peer)
{
    return (peer->state == NETWORK_PEER_STATE_DISCONNECTED);
}

void network_peer_address(struct network_peer* peer, struct network_address* out)
{
    memcpy(out, &peer->address, sizeof(struct network_address));
}

int network_peer_destroy(struct network_peer* peer)
{
    network_peer_reset(peer);

    int rc;
    JLFA(rc, peer->message_queue);
    peer->message_queue = NULL;

    JLFA(rc, peer->read_chunks);
    peer->read_chunks = NULL;

    free(peer);
    return 0;
}

int network_peer_update(struct network_peer* peer, int action_flags)
{
    int res; 
    socklen_t resl = (socklen_t)sizeof(res);

    switch(peer->state) {
    case NETWORK_PEER_STATE_READY:
        // not doing anything
        break;
    case NETWORK_PEER_STATE_CONNECTING:
        // Non-blocking connect() uses the write set during select
        if((action_flags & NETWORK_PEER_ACTION_FLAGS_WRITE) == 0) {
            // check timeout, abort if connection takes too long
            if((microtime() - peer->connect_time) >= (CONNECT_TIMEOUT * 1000000)) {
                network_peer_disconnect(peer, "connection timeout");
            }
            break;
        }

        if(getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, &res, &resl) < 0) {
            // Error on getsockopt, that's weird.
            network_peer_disconnect(peer, "getsockopt error");
            break;
        }

        if(res == 0) {
            // Socket ready
            peer->state = NETWORK_PEER_STATE_HANDSHAKING;
        } else {
            // TODO notify network manager that we couldn't connect
            peer_printf(peer, "couldn't connect (error = %d)\n", res);
            network_peer_disconnect(peer, "couldn't connect");
        }

        break;
    case NETWORK_PEER_STATE_HANDSHAKING:
        if(!peer->sent_version) {
            send_version(peer);
            peer->sent_version = 1;
        }
        // fall through

    case NETWORK_PEER_STATE_CONNECTED:
        // In both cases, we check if data is on the wire but handshaking only allows certain commands
        if((action_flags & NETWORK_PEER_ACTION_FLAGS_READ) != 0) do_read(peer);
        if((action_flags & NETWORK_PEER_ACTION_FLAGS_WRITE) != 0) do_write(peer);
        step(peer);
        break;
    default:
        break;
    }

    return 0;
}

static void do_read(struct network_peer* peer)
{
    do {
        unsigned char buf[READ_CHUNK_MAX_SIZE];
        ssize_t c = recv(peer->socket, buf, sizeof(buf), 0);

        // 0 = closed connection OR 0 bytes read
        // -1 = error or EWOULDBLOCK
        // n = # of bytes read, less than sizeof(buf) -> no more data
        if(c == 0) {
            // This is retarded. The manpage says "The value 0 may also be returned if the requested number of bytes to receive from a stream socket was 0."
            network_peer_disconnect(peer, "recv returned 0 (connection aborted)");
            return;
        } else if(c < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                // nothing left to read but connection is fine
                break;
            } else {
                // other error
                network_peer_disconnect(peer, "recv error");
                return;
            }
        } else {
            peer->total_read += c;

            struct read_chunk* chunk = NULL;
            Word_t index = peer->read_chunk_last - 1;
            struct read_chunk** pchunk = NULL;
            if(peer->read_chunk_next < peer->read_chunk_last) {
                JLG(pchunk, peer->read_chunks, index);   
                if(pchunk != NULL && ((*pchunk)->size + c) <= READ_CHUNK_MAX_SIZE) {
                    chunk = *pchunk;
                }
            }

            if(chunk == NULL) {
                chunk = (struct read_chunk*)malloc(sizeof(struct read_chunk));
                chunk->size = 0;
                chunk->head = &chunk->data[0];

                index = peer->read_chunk_last;
                JLI(pchunk, peer->read_chunks, index);
                if(pchunk == NULL) {
                    free(chunk);
                    network_peer_disconnect(peer, "read_chunk internal error");
                    return;
                }

                *pchunk = chunk;
                peer->read_chunk_last += 1;
            }

            memcpy(&chunk->data[chunk->size], buf, c);
            chunk->size += (size_t)c;
            peer->read_chunk_total += (size_t)c;

            // If we didn't get a full buffer there isn't any more to read
            if(c < sizeof(buf)) break;
        }
    } while (1);

    process_read_chunks(peer);
}

static void do_write(struct network_peer* peer)
{
    int rc;

    while( peer->message_queue_next < peer->message_queue_last ) {
        Word_t index = peer->message_queue_next;
        struct message** pmsg;
        JLG(pmsg, peer->message_queue, index);

        struct message* msg = *pmsg;
        size_t sent = (size_t)((uintptr_t)msg->head - (uintptr_t)msg->data);
        size_t left = msg->size - sent;

        ssize_t r = send(peer->socket, msg->head, left, 0);
        if(r < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            // outbound buffer is blocked..we can drop messages if we need to
            if((msg->flags & MESSAGE_MUST_SEND) == 0) {
                JLD(rc, peer->message_queue, index);
                free_message(msg);
                peer->message_queue_next += 1;
                continue;
            }

            // we can't send any more data, but this message must go through, so we're done
            break;
        } else {
            peer->total_write += r;

            if(r == left) {
                JLD(rc, peer->message_queue, index);
                free_message(msg);
                peer->message_queue_next += 1;
            } else {
                // didn't finish sending the message, but we've sent part of it 
                // so we need to finish sending it
                msg->flags |= MESSAGE_MUST_SEND;
                msg->head = (unsigned char*)((uintptr_t)msg->head + r);
                break;
            }
        }
    }
}

int network_peer_connect(struct network_peer* peer, struct network_address* address, size_t current_height)
{
    assert(peer->state == NETWORK_PEER_STATE_READY);
    memcpy(&peer->address, address, sizeof(struct network_address));

    peer->current_height = current_height;

    if(address->type == NETWORK_ADDRESS_TYPE_IPV4) {
        peer_printf(peer, "connecting\n");

        peer->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if(peer->socket < 0) {
            return -1;
        }

        int flags = fcntl(peer->socket, F_GETFL, 0);
        if (flags < 0) {
            close(peer->socket);
            return -1;
        }

        flags |= O_NONBLOCK;
        if(fcntl(peer->socket, F_SETFL, flags) != 0) {
            close(peer->socket);
            return -1;
        }
        
        struct sockaddr_in dest;
        dest.sin_addr = address->ipv4.addr;
        dest.sin_family = AF_INET;
        dest.sin_port = address->sin_port != 0 ? address->sin_port : NETWORK_DEFAULT_PORT;
        int res = connect(peer->socket, (struct sockaddr*)&dest, sizeof(struct sockaddr_in));
        peer->connect_time = microtime();
        if(res < 0 && errno != EINPROGRESS) {
            close(peer->socket);
            return -1;
        } else if(res == 0) {
            // Connect succeeded immediately
            peer->state = NETWORK_PEER_STATE_HANDSHAKING;
            peer_printf(peer, "connected (immediately?)\n");
            return 0;
        } else {
            // This is the most likely case. Fall through.
        }
    } else if(address->type == NETWORK_ADDRESS_TYPE_IPV6) {
        // TODO
        return -1;
    }

    peer->state = NETWORK_PEER_STATE_CONNECTING;
    network_manager_register_peer_for_polling(peer->nm, peer->socket, peer);

    return 0;
}

static void step(struct network_peer* peer)
{
    size_t r;
    uint64_t now = microtime();
    char* reason = "";

    if(peer->state != NETWORK_PEER_STATE_CONNECTED) return;

    // TODO Check if we have invs to send

    // if we send getblocks but never get an inv for a block then bail
    if(peer->getblocks_time != 0) {
        if(peer->getblocks_time != 0 && ((now - peer->getblocks_time) >= (PEER_GETBLOCKS_TIMEOUT * 1000000))) {
            reason = "getblocks timeout";
            goto bad;
        }
    }

    // Check if our previous getdatas are timing out (peer being unresponsive?)
    if(peer->getdata_block_waiting != 0) {
        if(peer->incoming_command != CMD_HASH_BLOCK) {
            // if we got an inv back for a block and have requested that block, but the peer doesn't respond, bail
            if(peer->getdata_block_time != 0 && ((now - peer->getdata_block_time) >= (PEER_BLOCK_TIMEOUT * 1000000))) {
                reason = "block timeout";
                goto bad;
            }
        } else {
            // TODO incoming command is a block, so check recv rate to see if they're DoSing
        }
    }

    if(peer->getdata_tx_waiting != 0) {
        if(peer->incoming_command != CMD_HASH_TX) {
            if(peer->getdata_tx_time != 0 && (now - peer->getdata_tx_time) >= (PEER_TX_TIMEOUT * 1000000)) {
                reason = "tx timeout";
                goto bad;
            }
        } else {
            // TODO incoming command is a tx, so check recv rate to see if they're DoSing
        }
    }

    // Check if there are getdatas to send. We only request transactions if there are no outstanding blocks
    if(peer->getdata_block_waiting == 0 && peer->getdata_tx_waiting == 0) {
        // Check if there are blocks we need to fetch (that we didn't get an inv for, i.e., the initial blockchain sync)
        if( peer->getblocks_time == 0 && (now - peer->last_getblocks_time) > (TIME_BETWEEN_GETBLOCKS * 1000000) && network_manager_should_send_getblocks(peer->nm, peer, peer->peer_height) == 1 ) {
            send_getblocks(peer);
            peer->getblocks_time = microtime();
            peer->last_getblocks_time = peer->getblocks_time;
        } else {
            struct inv block_inv[3];
            if((r = network_manager_get_invs(peer->nm, INV_TYPE_BLOCK, &block_inv[0], 3, 1)) > 0) {
                // TODO did the peer report this inv as notfound?
                if(network_manager_claim_invs(peer->nm, peer, &block_inv[0], r) == 0) {
                    mark_invs_as_requested(peer, &block_inv[0], r);
                    send_getdata(peer, &block_inv[0], r);
                    peer->getdata_block_waiting += r;
                    peer->getdata_block_time = microtime();
                    return;
                }
            } else {
                struct inv tx_invs[8];
                if((r = network_manager_get_invs(peer->nm, INV_TYPE_TX, &tx_invs[0], 8, 1)) > 0) {
                    // TODO did the peer report any of these invs as notfound?
                    if(network_manager_claim_invs(peer->nm, peer, &tx_invs[0], r) == 0) {
                        mark_invs_as_requested(peer, &tx_invs[0], r);
                        send_getdata(peer, &tx_invs[0], r);
                        peer->getdata_tx_waiting += r;
                        peer->getdata_tx_time = microtime();
                        return;
                    }
                }
            }
        }
    }

    // TODO Check if we have addrs to send
    return;
bad:
    network_peer_disconnect(peer, reason);
    return;
}

int peer_printf(struct network_peer* peer, char const* fmt, ...)
{
#ifdef LOG_STDOUT
    va_list ap;
    int i = 256;
    int j = 0;

    if(peer->address.type == NETWORK_ADDRESS_TYPE_IPV4) {
        j = printf("(%s:%d) ", inet_ntoa(peer->address.ipv4.addr), ntohs(peer->address.sin_port));
    } else if(peer->address.type == NETWORK_ADDRESS_TYPE_IPV6) {
        char s[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &peer->address.ipv6.addr, s, sizeof(s));
        j = printf("(%s:%d) ", s, ntohs(peer->address.sin_port));
    }

    do {
        char* buf = (char*)alloca(i);

        va_start(ap, fmt);
        int n = vsnprintf(buf, i, fmt, ap);
        va_end(ap);

        if(n > -1 && n < i) {
            printf("%s", buf);
            return j + n;
        }

        i <<= 1;
    } while(1);
#endif
    return 0;
}

static void process_read_chunks(struct network_peer* peer)
{
    while((peer->state == NETWORK_PEER_STATE_CONNECTED || peer->state == NETWORK_PEER_STATE_HANDSHAKING)) {
        // The network message overhead size is the minimum size of a message (with 0 payload)
        unsigned char buf[NETWORK_MESSAGE_OVERHEAD];
        size_t size = read_chunks(peer, buf, sizeof(buf), 1);

        // Not enough data? wait
        if(size < sizeof(buf)) break;

        size_t payload_size;
        int r = unserialize_network_message(buf, sizeof(buf), NULL, NULL, &payload_size);

        if(r != NETWORK_MESSAGE_OVERHEAD) {
            // Bad magic
            network_peer_disconnect(peer, "bad message magic");
            break;
        }

        // At this point, we have at least enough info to tell what command is incoming,
        // even if the full payload hasn't arrived.
        peer->incoming_command = sha256_first4(&buf[NETWORK_MESSAGE_COMMAND_OFFSET], NETWORK_MESSAGE_COMMAND_SIZE);

        // If message + payload has been delivered, go!
        size_t message_data_size = NETWORK_MESSAGE_OVERHEAD + payload_size;
        if(peer->read_chunk_total < message_data_size) break;

        unsigned char* message_data = alloca(message_data_size);
        if((size = read_chunks(peer, message_data, message_data_size, 0)) != message_data_size) {
            // This shouldn't happen
            assert(0);
            break;
        }

        unsigned char* payload;
        unsigned char command[NETWORK_MESSAGE_COMMAND_SIZE] = { 0, };
        r = unserialize_network_message(message_data, message_data_size, command, &payload, &payload_size);
        if(r != message_data_size) {
            // Bad checksum on payload
            network_peer_disconnect(peer, "bad message checksum");
            break;
        }

        handle_message(peer, command, payload, payload_size);
        peer->incoming_command = 0;
    }
}

static size_t read_chunks(struct network_peer* peer, unsigned char* out, size_t size, int peek)
{
    size_t total = 0;

    if(peer->read_chunk_next == peer->read_chunk_last) return 0;
    Word_t index = peer->read_chunk_next;

    unsigned char* read_ptr = NULL;
    size_t read_avail = 0;

    // First first read pointer
    struct read_chunk** pchunk = NULL, *chunk;
    JLG(pchunk, peer->read_chunks, index);
    assert(pchunk != NULL);
    chunk = *pchunk;
    read_ptr = chunk->head;
    read_avail = chunk->size - (size_t)((uintptr_t)chunk->head - (uintptr_t)&chunk->data[0]);

    while(index < peer->read_chunk_last) {
        size_t left = size - total;
        size_t c = (left < read_avail) ? left : read_avail;

        if(out != NULL) {
            memcpy(out, read_ptr, c);
            out = (unsigned char*)((uintptr_t)out + c);
        }

        read_ptr = (unsigned char*)((uintptr_t)read_ptr + c);
        read_avail -= c;

        if(peek == 0) {
            chunk->head = read_ptr;
            if(read_avail == 0) {
                // used up chunk
                int rc;
                JLD(rc, peer->read_chunks, index);
                free_read_chunk(chunk);
                peer->read_chunk_next += 1;
            }
            peer->read_chunk_total -= c;
        }

        total += c;
        if(total == size) break;
        else {
            assert(read_avail == 0);
            index += 1;

            if(index < peer->read_chunk_last) {
                pchunk = NULL;
                JLG(pchunk, peer->read_chunks, index);
                assert(pchunk != NULL);
                chunk = *pchunk;
                // never read this chunk before, so head better be at the beginning
                assert(chunk->head == &chunk->data[0]);
                read_ptr = chunk->head;
                read_avail = chunk->size;
            }
        }
    }

    return total;
}

static void queue_message(struct network_peer* peer, unsigned char const* message, size_t size, int flags)
{
    struct message* msg = (struct message*)malloc(sizeof(struct message));

    msg->flags = flags;
    msg->size = size;

    if((flags & MESSAGE_MUST_COPY) != 0) {
        msg->data = (unsigned char*)malloc(size);
        memcpy(msg->data, message, size);
    }

    // message head can move along if a partial send happens
    msg->head = msg->data;

    struct message** pmsg = NULL;
    Word_t index = peer->message_queue_last;
    JLI(pmsg, peer->message_queue, index);

    if(pmsg != NULL) {
        *pmsg = msg;
        peer->message_queue_last += 1;
    }
}

static void free_read_chunk(struct read_chunk* chunk)
{
    free(chunk);
}

static void free_message(struct message* msg)
{
    if((msg->flags & (MESSAGE_MUST_COPY | MESSAGE_MUST_FREE)) != 0) {
        free(msg->data);
    }
    free(msg);
}

static void mark_invs_as_requested(struct network_peer* peer, struct inv const* invs, size_t num_invs)
{
    for(size_t i = 0; i < num_invs; i++) {
        struct inv* inv = (struct inv*)malloc(sizeof(struct inv));
        memcpy(inv, &invs[i], sizeof(struct inv));

        Word_t* pi;
        JHSI(pi, peer->requested_invs, (unsigned char*)inv, sizeof(struct inv));
        assert(*pi == 0);

        Word_t index;
        (*pi) = index = (Word_t)peer->next_requested_inv_id;

        struct inv** pinv;
        JLI(pinv, peer->requested_invs_by_id, index);
        *pinv = inv;

        peer->next_requested_inv_id += 1;
    }
}

static void remove_invs_from_requested(struct network_peer* peer, struct inv const* invs, size_t num_invs)
{
    int rc;

    for(size_t i = 0; i < num_invs; i++) {
        Word_t* pi;
        JHSG(pi, peer->requested_invs, (unsigned char*)(&invs[i]), sizeof(struct inv));
        assert(pi != NULL);

        Word_t index = *pi;

        struct inv** pinv;
        JLG(pinv, peer->requested_invs_by_id, index);
        free(*pinv);

        JLD(rc, peer->requested_invs_by_id, index);
    }
}

static void send_version(struct network_peer* peer)
{
    size_t payload_size = 85 + serialize_string(NULL, NETWORK_USER_AGENT);

    size_t bufsize = NETWORK_MESSAGE_OVERHEAD + payload_size;
    unsigned char* buf = (unsigned char*)alloca(bufsize);
    unsigned char* payload = &buf[NETWORK_MESSAGE_OVERHEAD];

    size_t offset = 0;
    offset += serialize_uint32(&payload[offset], NETWORK_PROTOCOL_VERSION);
    offset += serialize_uint64(&payload[offset], NETWORK_NODE_SERVICES);
    offset += serialize_uint64(&payload[offset], (uint64_t)time(NULL));

    offset += serialize_network_address(&payload[offset], &peer->address, NETWORK_NODE_SERVICES, 0);
    offset += serialize_network_address(&payload[offset], NULL          , NETWORK_NODE_SERVICES, 0);

    peer->nonce = ((uint64_t)rand() << 32) | (uint64_t)rand();
    offset += serialize_uint64(&payload[offset], peer->nonce);
    offset += serialize_string(&payload[offset], NETWORK_USER_AGENT);

    unsigned long last_block = 320000; // TODO once block chain code is implemented
    offset += serialize_uint32(&payload[offset], last_block);

    offset += serialize_uint8(&payload[offset], 0x01); // always announce relayed transactions, we're not a "wallet" so we don't use bloom filtering

    size_t r = serialize_network_message(buf, "version", payload, payload_size);
    assert((r + payload_size) == bufsize);

    queue_message(peer, buf, bufsize, MESSAGE_MUST_COPY | MESSAGE_MUST_SEND);
}

static void send_verack(struct network_peer* peer)
{
    unsigned char buf[NETWORK_MESSAGE_OVERHEAD];
    size_t r = serialize_network_message(buf, "verack", (unsigned char*)"", 0);
    assert(r == NETWORK_MESSAGE_OVERHEAD);
    queue_message(peer, buf, sizeof(buf), MESSAGE_MUST_COPY | MESSAGE_MUST_SEND);
}

static void send_getdata(struct network_peer* peer, struct inv const* invs, size_t num_invs)
{
    assert(num_invs > 0);
    size_t payload_size = serialize_variable_uint(NULL, num_invs) + serialize_inv(NULL, &invs[0]) * num_invs;
    size_t bufsize = NETWORK_MESSAGE_OVERHEAD + payload_size;
    unsigned char* buf = (unsigned char*)alloca(bufsize);
    unsigned char* payload = &buf[NETWORK_MESSAGE_OVERHEAD];

    size_t offset = 0;
    offset += serialize_variable_uint(&payload[offset], (uint64_t)num_invs);
    assert(offset == 1);
    assert(serialize_inv(NULL, &invs[0]) == 36);

    for(size_t i = 0; i < num_invs; i++) {
        offset += serialize_inv(&payload[offset], &invs[i]);
    }

    size_t r = serialize_network_message(buf, "getdata", payload, payload_size);
    assert((r + payload_size) == bufsize);
    queue_message(peer, buf, bufsize, MESSAGE_MUST_COPY | MESSAGE_MUST_SEND);

    peer_printf(peer, "sent getdata for %d invs\n", num_invs);
}

static void send_getblocks(struct network_peer* peer)
{
    struct block_locator* block_locator = network_manager_block_locator(peer->nm);

    size_t payload_size = 4 + serialize_block_locator(NULL, block_locator) + 32;
    size_t bufsize = NETWORK_MESSAGE_OVERHEAD + payload_size;
    unsigned char* buf = (unsigned char*)alloca(bufsize);
    unsigned char* payload = &buf[NETWORK_MESSAGE_OVERHEAD];

    unsigned char stop_hash[32] = { 0, };
    size_t offset = 0;

    offset += serialize_uint32(&payload[offset], NETWORK_PROTOCOL_VERSION);
    offset += serialize_block_locator(&payload[offset], block_locator);
    offset += serialize_bytes(&payload[offset], stop_hash, 32);

    size_t r = serialize_network_message(buf, "getblocks", payload, payload_size);
    assert((r + payload_size) == bufsize);
    queue_message(peer, buf, bufsize, MESSAGE_MUST_COPY | MESSAGE_MUST_SEND);

    peer_printf(peer, "sent getblocks\n");

    block_locator_free(block_locator);
}

static void handle_message(struct network_peer* peer, unsigned char const* command, unsigned char const* payload, size_t payload_size)
{
    char* reason = "";
    unsigned long cmd = peer->incoming_command;

    // Anything outside of version and verack aren't accepted
    // until after handshake
    if(peer->state == NETWORK_PEER_STATE_HANDSHAKING) {
        if(cmd != CMD_HASH_VERACK && cmd != CMD_HASH_VERSION) {
            reason = "non-version command during handshake";
            goto bad;
        }
    }

    switch(cmd) {
    case CMD_HASH_ADDR:
        handle_addr(peer, payload, payload_size);
        break;
    case CMD_HASH_BLOCK:
        handle_block(peer, payload, payload_size);
        break;
    case CMD_HASH_INV:
        handle_inv(peer, payload, payload_size);
        break;
    case CMD_HASH_NOTFOUND:
        // TODO handle_notfound(peer, payload, payload_size);
        reason = "unhandled notfound";
        goto bad;
    case CMD_HASH_TX:
        handle_tx(peer, payload, payload_size);
        break;
    case CMD_HASH_VERACK:
        handle_verack(peer, payload, payload_size);
        break;
    case CMD_HASH_VERSION:
        handle_version(peer, payload, payload_size);
        break;
    default:
        {
            char buf[NETWORK_MESSAGE_COMMAND_SIZE + 1] = { 0, };
            memcpy(buf, command, NETWORK_MESSAGE_COMMAND_SIZE);
            peer_printf(peer, "got cmd %08X: %s\n", cmd, buf);
            break;
        }
    }

    return;
bad:
    network_peer_disconnect(peer, reason);
    return;
}

static void handle_version(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    size_t offset = 0;

    if(peer->received_version || peer->state != NETWORK_PEER_STATE_HANDSHAKING || payload_size < 80) goto bad;
    offset += unserialize_uint32(&payload[offset], payload_size - offset, &peer->peer_version);
    offset += unserialize_uint64(&payload[offset], payload_size - offset, &peer->peer_services);
    offset += unserialize_uint64(&payload[offset], payload_size - offset, &peer->peer_time);
    offset += unserialize_network_address(&payload[offset], payload_size - offset, &peer->my_address_from_peer, NULL, NULL);
    peer_printf(peer, "peer version %d\n", peer->peer_version);

    // We don't talk to old peers
    if(peer->peer_version < 60002) goto bad;
    offset += unserialize_network_address(&payload[offset], payload_size - offset, NULL, NULL, NULL);
    offset += unserialize_uint64(&payload[offset], payload_size - offset, &peer->peer_nonce);

    size_t user_agent_length = 0;
    size_t len = unserialize_string(&payload[offset], payload_size - offset, NULL, &user_agent_length);
    if(len == 0) goto bad;

    peer->peer_user_agent = (char *)malloc(sizeof(char) * (user_agent_length + 1));
    memset(peer->peer_user_agent, 0, sizeof(char) * (user_agent_length + 1));
    offset += unserialize_string(&payload[offset], payload_size - offset, peer->peer_user_agent, &user_agent_length);

    if((offset + 4) > payload_size) goto bad;
    offset += unserialize_uint32(&payload[offset], payload_size - offset, &peer->peer_height);

    peer->peer_full_relay = 1;
    if(peer->peer_version >= 70001) {
        // Weird, it looks like some 70001 clients don't sent the relay flag..?
        if(peer->peer_version >= 70002 && ((offset + 1) > payload_size)) goto bad;
        if((offset + 1) <= payload_size) {
            offset += unserialize_uint8(&payload[offset], payload_size - offset, &peer->peer_full_relay);
        }
    }

    peer->received_version = 1;
    peer->handshake_step += 1;
    send_verack(peer);

    if(peer->handshake_step == 2) {
        peer->state = NETWORK_PEER_STATE_CONNECTED;
    }

    return;

bad:
    network_peer_disconnect(peer, "bad version");
    return;
}

static void handle_verack(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    if(!peer->sent_version || (peer->state != NETWORK_PEER_STATE_HANDSHAKING)) goto bad;

    peer->handshake_step += 1;
    if(peer->handshake_step == 2) {
        peer->state = NETWORK_PEER_STATE_CONNECTED;
    }

    return;
bad:
    network_peer_disconnect(peer, "bad verack");
    return;
}

static void handle_addr(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    size_t r, offset = 0;

    uint64_t count = 0;
    offset += (r = unserialize_variable_uint(&payload[offset], payload_size - offset, &count));

    if(r == 0) {
        peer_printf(peer, "peer sent bad addr command");
        goto bad;
    }

    if(count > 1000) {
        peer_printf(peer, "peer sent too many addresses");
        goto bad;
    }

    for(size_t i = 0; i < count; i++) {
        struct network_address address;
        unsigned int timestamp;
        uint64_t services;
        offset += (r = unserialize_network_address(&payload[offset], payload_size - offset, &address, &services, &timestamp));
        if(r == 0) {
            peer_printf(peer, "peer sent bad addr command (i=%d)", (int)i);
            goto bad;
        }
        network_manager_handle_addr(peer->nm, peer, &address, services, timestamp);
    }

    return;
bad:
    network_peer_disconnect(peer, "bad addr");
    return;
}

static void handle_block(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    size_t offset = 0;
    struct block* block = NULL;

    // Sanity check the payload size, as we don't want to deserialize something ridiculously large
    if(payload_size > (2*BLOCK_MAX_SERIALIZE_SIZE)) {
        peer_printf(peer, "peer sent a large block");
        goto bad;
    }

    offset += unserialize_block(&payload[offset], payload_size - offset, &block);
    if(offset != payload_size || block == NULL) {
        peer_printf(peer, "bad payload size %d but unserialize_block took %d bytes\n", payload_size, offset);
        goto bad;
    }

#if 1
    {
        // See if we serialize correctly
        size_t size = block_size(block);
        assert(size == payload_size);
        unsigned char* buf = alloca(size);
        serialize_block(buf, block);
        assert(memcmp(buf, payload, size) == 0);
    }
#endif

    // We have a block, so hash it and mark it as received
    struct inv inv;
    inv.type = INV_TYPE_BLOCK;
    block_header_hash(block_header(block), inv.hash);

    // If peer sent us a block we didn't request, bail
    Word_t* pi;
    JHSG(pi, peer->requested_invs, (unsigned char*)&inv, sizeof(struct inv));
    if(pi == NULL) {
        bytes_to_hexstring(inv.hash, 32, s, 1);
        peer_printf(peer, "weird, received a block that we didn't request: %s\n", s);
        goto bad;
    }

    remove_invs_from_requested(peer, &inv, 1);

    bytes_to_hexstring(inv.hash, BLOCK_HASH_SIZE, s, 1);
    peer_printf(peer, "got block %s\n", s);

    peer->getdata_block_waiting -= 1;
    network_manager_handle_block(peer->nm, peer, &inv, block);
    return;
bad:
    if(block != NULL) block_free(block);
    network_peer_disconnect(peer, "bad block");
    return;
}

static void handle_inv(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    size_t offset = 0;
    uint64_t c;

    offset += unserialize_variable_uint(&payload[offset], payload_size - offset, &c);
    if(offset == 0) goto bad;

    // TODO better sanity
    if(c >= 1024) goto bad;

    for(uint64_t i = 0; i < c; i++) {
        struct inv inv;
        size_t r = unserialize_inv(&payload[offset], payload_size - offset, &inv);
        if(r == 0) goto bad;
        offset += r;

        if(inv.type == INV_TYPE_BLOCK) {
            // It doesn't matter if this inv is from a getblocks, we now know about at least one block
            // and can request more blocks only after we finish retriving known ones
            peer->getblocks_time = 0;
        }

        network_manager_handle_inv(peer->nm, peer, &inv);
    }

    return;
bad:
    network_peer_disconnect(peer, "bad inv");
    return;
}

static void handle_tx(struct network_peer* peer, unsigned char const* payload, size_t payload_size)
{
    size_t offset = 0;
    struct transaction* tx = NULL;

    offset += unserialize_transaction(&payload[offset], payload_size - offset, &tx);
    if(offset != payload_size || tx == NULL) goto bad;

#if 1
    {
        // See if we serialize correctly
        size_t tx_size = transaction_size(tx);
        assert(tx_size == payload_size);
        unsigned char* buf = alloca(tx_size);
        serialize_transaction(buf, tx);
        assert(memcmp(buf, payload, tx_size) == 0);
    }
#endif

    // We have a transaction, so hash it and mark it as received
    struct inv inv;
    inv.type = INV_TYPE_TX;
    transaction_hash(tx, inv.hash);

    // If peer sent us a tx we didn't request, bail
    Word_t* pi;
    JHSG(pi, peer->requested_invs, (unsigned char*)&inv, sizeof(struct inv));
    if(pi == NULL) goto bad;

    remove_invs_from_requested(peer, &inv, 1);

    bytes_to_hexstring(inv.hash, TRANSACTION_HASH_SIZE, s, 1);
    peer_printf(peer, "got tx %s\n", s);

    peer->getdata_tx_waiting -= 1;
    network_manager_handle_tx(peer->nm, peer, &inv, tx);
    return;
bad:
    network_peer_disconnect(peer, "bad tx");
    return;
}

