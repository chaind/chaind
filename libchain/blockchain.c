#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gmp.h>
#include <Judy.h>

#include "block.h"
#include "blockchain.h"
#include "hashes.h"
#include "serialize.h"
#include "util.h"

struct block_locator {
    size_t size;
    void*  hashes;
};

struct blockchain_link {
    struct       block_header* header;
    int          connected;
    int          main;
    int          height;
    mpz_t        work; // Running sum
    unsigned int median_time_past;

    uintptr_t    data;
    struct blockchain_link* (*previous_link)(struct blockchain_link*, uintptr_t, int, size_t);
};

void block_locator_free(struct block_locator* block_locator)
{
    for(size_t i = 0; i < block_locator->size; i++) {
        Word_t index = (Word_t)i;
        unsigned char** phash;
        JLG(phash, block_locator->hashes, index);
        free(*phash);
    }

    int rc;
    JLFA(rc, block_locator->hashes);
    free(block_locator);
}

size_t serialize_block_locator(unsigned char* out, struct block_locator const* block_locator)
{
    size_t offset = 0;

    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)block_locator->size);

    for(size_t i = 0; i < block_locator->size; i++) {
        Word_t index = (Word_t)i;
        unsigned char** phash;
        JLG(phash, block_locator->hashes, index);
        offset += serialize_bytes(out == NULL ? NULL : &out[offset], *phash, 32);
    }

    return offset;
}

struct blockchain_link* blockchain_link_new()
{
    struct blockchain_link* link = (struct blockchain_link*)malloc(sizeof(struct blockchain_link));
    zero(link);

    link->header = block_header_new();
    mpz_init(link->work);

    return link;
}

void blockchain_link_free(struct blockchain_link* link)
{
    mpz_clear(link->work);
    block_header_free(link->header);
    free(link);
}

struct block_header* blockchain_link_block_header(struct blockchain_link* link)
{
    return link->header;
}

int blockchain_link_main(struct blockchain_link* link)
{
    return link->main;
}

int blockchain_link_connected(struct blockchain_link* link)
{
    return link->connected;
}

unsigned int blockchain_link_height(struct blockchain_link* link)
{
    return link->height;
}

unsigned int blockchain_link_median_time_past(struct blockchain_link* link)
{
    return link->median_time_past;
}

void blockchain_link_work(struct blockchain_link* link, mpz_t work)
{
    mpz_set(work, link->work);
}

void blockchain_link_set_main(struct blockchain_link* link, int main)
{
    link->main = main;
}

void blockchain_link_set_connected(struct blockchain_link* link, int connected)
{
    link->connected = connected;
}

void blockchain_link_set_height(struct blockchain_link* link, unsigned int height)
{
    link->height = height;
}

void blockchain_link_set_median_time_past(struct blockchain_link* link, unsigned int median_time_past)
{
    link->median_time_past = median_time_past;
}

void blockchain_link_set_work(struct blockchain_link* link, mpz_t work)
{
    mpz_clear(link->work);
    mpz_init_set(link->work, work);
}

void blockchain_link_set_previous_link(struct blockchain_link* link, PREVIOUS_LINK_FUNCTION* previous_link, uintptr_t data)
{
    link->previous_link = previous_link;
    link->data = data;
}

struct blockchain_link* blockchain_link_previous_link(struct blockchain_link* link, int by_count, size_t count)
{
    return link->previous_link(link, link->data, by_count, count);
}

// boi - beginning of work interval.  boi must be height % WORK_INTERVAL = 0 and (link height - boi height < WORK_INTERVAL)
unsigned int blockchain_link_get_next_bits(struct blockchain_link* link, struct blockchain_link* boi, unsigned int next_block_timestamp)
{
    assert((blockchain_link_height(boi) % WORK_RETARGET_INTERVAL) == 0);
    assert((blockchain_link_height(link) - blockchain_link_height(boi)) <= WORK_RETARGET_INTERVAL);

    if(((blockchain_link_height(link) + 1) % WORK_RETARGET_INTERVAL) != 0) {
#if 0
        // TODO testnet has special retargetting rules
#else
        return block_header_bits(blockchain_link_block_header(link));
#endif
    }

    // Clamp target to limited range
    unsigned int timespan = block_header_timestamp(blockchain_link_block_header(link)) - block_header_timestamp(blockchain_link_block_header(boi));
    timespan = MAX(timespan, WORK_RETARGET_TIMESPAN / 4);
    timespan = MIN(timespan, WORK_RETARGET_TIMESPAN * 4);

    mpz_t timespan_big;
    mpz_init_set_ui(timespan_big, timespan);

    mpz_t target;
    bits_to_target(block_header_bits(blockchain_link_block_header(link)), target);
    mpz_mul(target, target, timespan_big);
    mpz_div_ui(target, target, WORK_RETARGET_TIMESPAN);

    mpz_t difficulty_limit;
    bits_to_target(BLOCK_DIFFICULTY_LIMIT_BITS, difficulty_limit);

    if(mpz_cmp(target, difficulty_limit) > 0) {
        mpz_clear(target);
        bits_to_target(BLOCK_DIFFICULTY_LIMIT_BITS, target);
    }

    unsigned int bits = target_to_bits(target);

    mpz_clear(difficulty_limit);
    mpz_clear(target);
    mpz_clear(timespan_big);

    return bits;
}

struct block_locator* blockchain_link_block_locator(struct blockchain_link* link)
{
    struct block_locator* block_locator = (struct block_locator*)malloc(sizeof(struct block_locator));
    zero(block_locator);

    size_t step = 1;
    struct block_header* header;

    // add 'link'
    header = blockchain_link_block_header(link);

    // put hash in list
    unsigned char** phash;
    Word_t i = (Word_t)block_locator->size;
    JLI(phash, block_locator->hashes, i);
    *phash = (unsigned char*)malloc(sizeof(unsigned char) * 32);
    block_header_hash(header, *phash);
    block_locator->size += 1;

    // first link doesn't get freed
    link = blockchain_link_previous_link(link, 0, 0);

    while(link != NULL) {
        header = blockchain_link_block_header(link);

        // put hash in list
        i = (Word_t)block_locator->size;
        JLI(phash, block_locator->hashes, i);
        *phash = (unsigned char*)malloc(sizeof(unsigned char) * 32);
        block_header_hash(header, *phash);
        block_locator->size += 1;

        // step
        if(block_locator->size >= 10) step *= 2;

        for(size_t j = 0; j < step && link != NULL; j++) {
            if(blockchain_link_main(link) && blockchain_link_height(link) == 0) {
                blockchain_link_free(link);
                link = NULL;
            } else if(step > 1 && blockchain_link_main(link)) {
                // Compute how far to jump. If we're on the main chain we can just lookup the block by height
                size_t count = step - j; 
                size_t height = blockchain_link_height(link);
                count = MIN(count, height);

                struct blockchain_link* prev = blockchain_link_previous_link(link, 1, count);
                blockchain_link_free(link);
                link = prev;

                // We've skipped ahead, so we're done.
                break;
            } else {
                struct blockchain_link* prev = blockchain_link_previous_link(link, 0, 0);
                blockchain_link_free(link);
                link = prev;
            }
        }
    }

    return block_locator;
}

