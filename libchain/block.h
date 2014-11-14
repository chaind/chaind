#ifndef __BLOCK_H
#define __BLOCK_H

#define BLOCK_HASH_SIZE 32
#define BLOCK_DIFFICULTY_LIMIT_BITS 0x1d00ffff
#define BLOCK_MAX_SERIALIZE_SIZE 1000000
#define BLOCK_MAX_SIGOPS (BLOCK_MAX_SERIALIZE_SIZE / 50)
#define BLOCK_COINBASE_SPENDING_AGE 100

#include <gmp.h>

struct block_header;
struct block;
struct transaction;

struct block_header* block_header_new();
struct block_header* block_header_clone(struct block_header const*);
void block_header_work(struct block_header*, mpz_t ret);
void block_header_set_version(struct block_header*, unsigned int);
void block_header_set_previous_block_hash(struct block_header*, unsigned char const*);
void block_header_set_merkle_root(struct block_header*, unsigned char const*);
void block_header_set_timestamp(struct block_header*, unsigned int);
void block_header_set_bits(struct block_header*, unsigned int);
void block_header_set_nonce(struct block_header*, unsigned int);
void block_header_free(struct block_header*);

int block_header_version(struct block_header const*);
void block_header_previous_block_hash(struct block_header const*, unsigned char* out);
void block_header_merkle_root(struct block_header const*, unsigned char* out);
unsigned int block_header_timestamp(struct block_header const*);
unsigned int block_header_bits(struct block_header const*);
unsigned int block_header_nonce(struct block_header const*);
void block_header_hash(struct block_header const*, unsigned char* out);
int block_header_valid(struct block_header const* header);

struct block* block_new();
void block_free(struct block*);

struct block_header* block_header(struct block*);
size_t block_num_transactions(struct block const*);
struct transaction* block_transaction(struct block*, size_t);
void block_add_transaction(struct block*, struct transaction*);
int block_calculate_merkle_root(struct block*, unsigned char*);

struct block* block_genesis();


size_t serialize_block(unsigned char* out, struct block const*);
size_t unserialize_block(unsigned char const* in, size_t in_size, struct block** out);

static inline size_t block_size(struct block const* block) 
{
    return serialize_block(NULL, block);
}

#endif
