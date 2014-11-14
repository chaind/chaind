#ifndef __DATABASE_BLOCKCHAIN_H
#define __DATABASE_BLOCKCHAIN_H

#include <gmp.h>

struct _bson_t;
typedef struct _bson_t bson_t;

struct block;
struct blockchain_link;
struct database;
struct vector;

int database_create_blockchain_indexes(struct database*);

struct block* database_get_block(struct database*, unsigned char* block_hash);
int database_has_block(struct database*, unsigned char const*);
int database_add_disconnected_block(struct database*, unsigned char const*, struct block*);
int database_connect_block(struct database*, unsigned char* block_hash, struct blockchain_link*);
struct blockchain_link* database_get_blockchain_link(struct database*, unsigned char* block_hash);
struct blockchain_link* database_get_main_blockchain_link_at_height(struct database*, size_t height);
struct blockchain_link* database_get_best_blockchain_link(struct database*);
int database_find_blockchain_links_by_previous_block_hash(struct database*, unsigned char* previous_block_hash, struct vector* result);
int database_set_median_time_past(struct database* db, unsigned char* block_hash, size_t nblocks);

void block_bson(struct block*, bson_t* out);
struct block* block_from_bson(bson_t const*, struct vector*);
struct blockchain_link* blockchain_link_from_bson(bson_t const*);

#endif /* __DATABASE_BLOCKCHAIN_H */
