#ifndef __NETWORK_MANAGER_H
#define __NETWORK_MANAGER_H

#define NETWORK_DEFAULT_PORT     8333
#define NETWORK_PROTOCOL_VERSION 70001
#define NETWORK_NODE_SERVICES    1
#define NETWORK_USER_AGENT       "/Satoshi:0.7.2/" // TODO change later

enum INV_TYPE;

struct block;
struct chaind;
struct inv;
struct network_address;
struct network_manager;
struct network_peer;
struct transaction;

struct network_manager* network_manager_create(struct chaind*);
int network_manager_update(struct network_manager*);
int network_manager_destroy(struct network_manager*);

int network_manager_listen(struct network_manager*);
struct network_peer* network_manager_get_peer_by_address(struct network_manager*, struct network_address*);
int network_manager_register_peer_for_polling(struct network_manager*, int, struct network_peer*);
int network_manager_unregister_peer_for_polling(struct network_manager*, struct network_peer*);

void network_manager_handle_addr(struct network_manager*, struct network_peer*, struct network_address*, uint64_t services, unsigned int timestamp);
void network_manager_handle_block(struct network_manager*, struct network_peer*, struct inv const*, struct block*);
void network_manager_handle_tx(struct network_manager*, struct network_peer*, struct inv const*, struct transaction*);

void network_manager_handle_inv(struct network_manager*, struct network_peer*, struct inv const*);
size_t network_manager_get_invs(struct network_manager*, enum INV_TYPE invtype, struct inv* out, size_t num_invs, int skip_claimed);
int network_manager_claim_invs(struct network_manager*, struct network_peer*, struct inv const* invs, size_t num_invs);
void network_manager_unclaim_invs(struct network_manager*, struct network_peer*, struct inv const* invs, size_t num_invs);

int network_manager_should_send_getblocks(struct network_manager*, struct network_peer*, size_t peer_height);
struct block_locator* network_manager_block_locator(struct network_manager*);

#endif /* __NETWORK_MANAGER_H */
