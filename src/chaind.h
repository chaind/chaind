#ifndef __CHAIND_H
#define __CHAIND_H

struct block;
struct blockchain_link;
struct chaind;
struct config;
struct database;
struct inv;
struct memory_pool;
struct transaction;

struct chaind* chaind_init(struct config*);
int chaind_deinit(struct chaind*);
int chaind_update(struct chaind*);

void chaind_request_exit(struct chaind*);

int chaind_handle_block(struct chaind*, struct inv const*, struct block*);
int chaind_handle_tx(struct chaind*, struct inv const*, struct transaction*);

struct blockchain_link* chaind_best_blockchain_link(struct chaind*);
struct config* chaind_config(struct chaind*);
struct database* chaind_database(struct chaind*);
struct memory_pool* chaind_memory_pool(struct chaind*);

#endif /* __CHAIND_H */
