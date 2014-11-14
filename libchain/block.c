#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>

#include "block.h"
#include "hashes.h"
#include "serialize.h"
#include "transaction.h"
#include "util.h"

struct block_header {
    unsigned int version;
    unsigned char previous_block_hash[32];
    unsigned char merkle_root[32];
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;
};

struct block {
    struct block_header header;
    void* transactions;

    size_t num_transactions;
};

struct block_header* block_header_new()
{
    struct block_header* out = (struct block_header*)malloc(sizeof(struct block_header));
    zero(out);
    return out;
}

struct block_header* block_header_clone(struct block_header const* in)
{
    struct block_header* out = (struct block_header*)malloc(sizeof(struct block_header));
    memcpy(out, in, sizeof(struct block_header));
    return out;
}

void block_header_work(struct block_header* header, mpz_t ret)
{
    mpz_set_ui(ret, 1);
    mpz_mul_2exp(ret, ret, 256);

    mpz_t target;
    mpz_init(target);
    bits_to_target(header->bits, target);

    if(mpz_cmp_ui(target, 0) < 0) {
        mpz_clear(target);
        mpz_set_ui(ret, 0);
        return;
    }

    mpz_add_ui(target, target, 1);
    mpz_tdiv_q(ret, ret, target);
}

void block_header_set_version(struct block_header* header, unsigned int version)
{
    header->version = version;
}

void block_header_set_previous_block_hash(struct block_header* header, unsigned char const* previous_block_hash)
{
    memcpy(header->previous_block_hash, previous_block_hash, 32);
}

void block_header_set_merkle_root(struct block_header* header, unsigned char const* merkle_root)
{
    memcpy(header->merkle_root, merkle_root, 32);
}

void block_header_set_timestamp(struct block_header* header, unsigned int timestamp)
{
    header->timestamp = timestamp;
}

void block_header_set_bits(struct block_header* header, unsigned int bits)
{
    header->bits = bits;
}

void block_header_set_nonce(struct block_header* header, unsigned int nonce)
{
    header->nonce = nonce;
}

void block_header_free(struct block_header* header)
{
    free(header);
}

void block_header_hash(struct block_header const* block_header, unsigned char* out)
{
    // Depends on little-endian memory
    sha256_sha256((unsigned char*)block_header, sizeof(struct block_header), out);
}

int block_header_version(struct block_header const* header)
{
    return header->version;
}

void block_header_previous_block_hash(struct block_header const* header, unsigned char* out)
{
    memcpy(out, header->previous_block_hash, 32);
}

void block_header_merkle_root(struct block_header const* header, unsigned char* out)
{
    memcpy(out, header->merkle_root, 32);
}

unsigned int block_header_timestamp(struct block_header const* header)
{
    return header->timestamp;
}

unsigned int block_header_bits(struct block_header const* header)
{
    return header->bits;
}

unsigned int block_header_nonce(struct block_header const* header)
{
    return header->nonce;
}

int block_header_valid(struct block_header const* header)
{
    unsigned char hash_str[32];
    block_header_hash(header, hash_str);

    // Import hash as a little-endian number
    mpz_t hash;
    mpz_init(hash);
    mpz_import(hash, 32, -1, sizeof(hash_str[0]), 1, 0, hash_str);

    mpz_t target;
    mpz_init(target);
    bits_to_target(header->bits, target);

    int result = 0;
    if(mpz_cmp(hash, target) <= 0) {
        result = 1;
    }

    mpz_clear(target);
    mpz_clear(hash);

    return result;
}

struct block_header* block_header(struct block* block)
{
    return &block->header;
}

struct block* block_genesis()
{
    static struct block genesis = {
        { 
            1,
            { 0, },
            { 0, },
            1231006505,
            0x1d00ffff,
            2083236893
        },
        NULL,
        0
    };

    if(genesis.transactions == NULL) {
        struct transaction* genesis_coinbase = transaction_genesis_coinbase();
        transaction_hash(genesis_coinbase, genesis.header.merkle_root);

        struct transaction** ptx;
        Word_t index = 0;
        JLI(ptx, genesis.transactions, index);
        assert(ptx != NULL);
        *ptx = genesis_coinbase;
        genesis.num_transactions += 1;
    }

    return &genesis;
}

struct block* block_new()
{
    struct block* block = (struct block*)malloc(sizeof(struct block));
    zero(block);
    return block;
}

void block_free(struct block* block)
{
    //TODO free block->transactions
    free(block);
}

size_t block_num_transactions(struct block const* block)
{
    return block->num_transactions;
}

struct transaction* block_transaction(struct block* block, size_t index)
{
    Word_t i = (Word_t)index;
    struct transaction** ptx;
    JLG(ptx, block->transactions, i);
    return ptx != NULL ? *ptx : NULL;
}

void block_add_transaction(struct block* block, struct transaction* tx)
{
    Word_t i = (Word_t)block->num_transactions;
    struct transaction** ptx;
    JLI(ptx, block->transactions, i);
    *ptx = tx;
    block->num_transactions += 1;
}

int block_calculate_merkle_root(struct block* block, unsigned char* out)
{
    // This code follows the same strategy as CBlock::BuildMerkleTree in Bitcoin Core,
    // also taking into account the duplicate hash vulnerability CVE-2012-2459.
    // If the vulnerability is seen, -1 is returned and "out" is not set, otherwise
    // 0 is returned with "out" containing the merkel root of the block.

    size_t num_transactions = block_num_transactions(block);
    unsigned char* storage = (unsigned char*)malloc((sizeof(unsigned char) * 32) * (num_transactions * 2 + 16));
    unsigned int storage_index = 0;

    #define MERKLE_ROOT_STORAGE(_i) (&storage[(_i)*32])

    for(size_t i = 0; i < num_transactions; i++) {
        transaction_hash(block_transaction(block, i), MERKLE_ROOT_STORAGE(i));
        storage_index += 1;
    }

    size_t level = 0;
    for(size_t i = num_transactions; i > 1; i = (i + 1) / 2) {
        for(size_t j = 0; j < i; j += 2) {
            size_t j2 = MIN(j + 1, i - 1);

            unsigned char* h1 = MERKLE_ROOT_STORAGE(level + j);
            unsigned char* h2 = MERKLE_ROOT_STORAGE(level + j2);

            if(j2 == (j + 1) && (j2 + 1) == i && memcmp(MERKLE_ROOT_STORAGE(level + j), MERKLE_ROOT_STORAGE(level + j2), 32) == 0) {
                // duplicate hash found
                free(storage);
                return -1;
            }

            unsigned char src[64];
            memcpy(src, h1, 32);
            memcpy(&src[32], h2, 32);
            sha256_sha256(src, 64, MERKLE_ROOT_STORAGE(storage_index));
            storage_index += 1;
        }

        level += i;
    }

    if(storage_index > 0) {
        memcpy(out, MERKLE_ROOT_STORAGE(storage_index-1), 32);
    } else {
        memset(out, 0, 32);
    }

    #undef MERKLE_ROOT_STORAGE

    free(storage);
    return 0;
}

size_t serialize_block_header(unsigned char* out, struct block_header const* header)
{
    size_t offset = 0;

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], header->version);
    offset += serialize_bytes(out == NULL ? NULL : &out[offset], &header->previous_block_hash[0], 32);
    offset += serialize_bytes(out == NULL ? NULL : &out[offset], &header->merkle_root[0], 32);
    offset += serialize_uint32(out == NULL ? NULL : &out[offset], header->timestamp);
    offset += serialize_uint32(out == NULL ? NULL : &out[offset], header->bits);
    offset += serialize_uint32(out == NULL ? NULL : &out[offset], header->nonce);

    return offset;
}

size_t serialize_block(unsigned char* out, struct block const* block)
{
    size_t offset = 0;

    offset += serialize_block_header(out == NULL ? NULL : &out[offset], &block->header);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], block->num_transactions);

    for(size_t i = 0; i < block->num_transactions; i++) {
        Word_t index = (Word_t)i;
        struct transaction** ptx;
        JLG(ptx, block->transactions, index);
        offset += serialize_transaction(out == NULL ? NULL : &out[offset], *ptx);
    }

    return offset;
}

size_t unserialize_block_header(unsigned char const* in, size_t in_size, struct block_header* out)
{
    size_t offset = 0;
    if(in_size < sizeof(struct block_header)) return 0;

    offset += unserialize_uint32(&in[offset], in_size - offset, &out->version);
    offset += unserialize_bytes(&in[offset], in_size - offset, &out->previous_block_hash[0], 32);
    offset += unserialize_bytes(&in[offset], in_size - offset, &out->merkle_root[0], 32);
    offset += unserialize_uint32(&in[offset], in_size - offset, &out->timestamp);
    offset += unserialize_uint32(&in[offset], in_size - offset, &out->bits);
    offset += unserialize_uint32(&in[offset], in_size - offset, &out->nonce);

    return offset;
}

size_t unserialize_block(unsigned char const* in, size_t in_size, struct block** out)
{
    size_t r, offset = 0;
    struct block* block = (struct block*)malloc(sizeof(struct block));
    zero(block);

    if(in_size < sizeof(struct block_header)) goto bad;
    offset += unserialize_block_header(&in[offset], in_size - offset, &block->header);

    uint64_t num_transactions;
    offset += (r = unserialize_variable_uint(&in[offset], in_size - offset, &num_transactions));
    if(r == 0) goto bad;

    for(size_t i = 0; i < (size_t)num_transactions; i++) {
        struct transaction* tx;
        offset += (r = unserialize_transaction(&in[offset], in_size - offset, &tx));
        if(r == 0) goto bad;

        Word_t index = (Word_t)block->num_transactions;
        struct transaction** ptx;
        JLI(ptx, block->transactions, index);
        *ptx = tx;
        block->num_transactions += 1;
    }

    *out = block;
    return offset;
bad:
    if(block != NULL) block_free(block);
    return 0;
}

