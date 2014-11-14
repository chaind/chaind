#ifndef __NETWORK_PEER_H
#define __NETWORK_PEER_H

struct network_manager;
struct network_peer;
struct network_address;

#define NETWORK_PEER_ACTION_FLAGS_READ      0x01
#define NETWORK_PEER_ACTION_FLAGS_WRITE     0x02
#define NETWORK_PEER_ACTION_FLAGS_EXCEPTION 0x04

struct network_peer* network_peer_create(struct network_manager*);
int network_peer_update(struct network_peer*, int action_flags);
int network_peer_destroy(struct network_peer*);

int network_peer_connect(struct network_peer*, struct network_address*, size_t current_height);
void network_peer_disconnect(struct network_peer*, char const*);
int network_peer_disconnected(struct network_peer*);
void network_peer_address(struct network_peer*, struct network_address*);

#endif /* __NETWORK_PEER_H */
