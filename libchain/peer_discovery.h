#ifndef __PEER_DISCOVERY_H
#define __PEER_DISCOVERY_H

struct peer_discovery;
struct network_address;

struct peer_discovery* peer_discovery_start();
int peer_discovery_get(struct peer_discovery*, struct network_address* out);
void peer_discovery_done(struct peer_discovery*);

#endif /* __PEER_DISCOVERY_H */
