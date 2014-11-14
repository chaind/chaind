#ifndef __BLOCKCHAIN_H
#define __BLOCKCHAIN_H

// 10 minute blocks
#define TARGET_BLOCK_SPACING  (10 * 60)

// Retarget every 2 weeks
#define WORK_RETARGET_TIMESPAN (14 * 24 * 60 * 60)

// Retarget every X blocks
#define WORK_RETARGET_INTERVAL (WORK_RETARGET_TIMESPAN / TARGET_BLOCK_SPACING)

// Median Time Past interval
#define MEDIAN_TIME_PAST_INTERVAL 11

// Initial block reward
#define INITIAL_BLOCK_REWARD 5000000000ULL

// Max coins
#define TOTAL_COINS 2100000000000000ULL

// BIP16 P2SH switch time
#define BIP16_SWITCH_TIME 1333238400

// Two BIP30 approved blocks
#define BIP30_BLOCK_91842_HASH "\xec\xca\xe0\x00\xe3\xc8\xe4\xe0\x93\x93\x63\x60\x43\x1f\x3b\x76\x03\xc5\x63\xc1\xff\x61\x81\x39\x0a\x4d\x0a\x00\x00\x00\x00\x00"
#define BIP30_BLOCK_91880_HASH "\x21\xd7\x7c\xcb\x4c\x08\x38\x6a\x04\xac\x01\x96\xae\x10\xf6\xa1\xd2\xc2\xa3\x77\x55\x8c\xa1\x90\xf1\x43\x07\x00\x00\x00\x00\x00"

#include <stdint.h>
#include <gmp.h>

struct block_header;
struct block_locator;
struct blockchain_link;

void block_locator_free(struct block_locator*);

size_t serialize_block_locator(unsigned char* out, struct block_locator const*);

typedef struct blockchain_link* (PREVIOUS_LINK_FUNCTION)(struct blockchain_link*, uintptr_t, int, size_t);

struct blockchain_link* blockchain_link_new();
struct block_header* blockchain_link_block_header(struct blockchain_link*);
int blockchain_link_main(struct blockchain_link*);
int blockchain_link_connected(struct blockchain_link*);
unsigned int blockchain_link_height(struct blockchain_link*);
unsigned int blockchain_link_median_time_past(struct blockchain_link*);
void blockchain_link_work(struct blockchain_link*, mpz_t work);
void blockchain_link_set_main(struct blockchain_link*, int main);
void blockchain_link_set_connected(struct blockchain_link*, int connected);
void blockchain_link_set_height(struct blockchain_link*, unsigned int height);
void blockchain_link_set_median_time_past(struct blockchain_link*, unsigned int);
void blockchain_link_set_work(struct blockchain_link*, mpz_t work);
void blockchain_link_set_previous_link(struct blockchain_link*, PREVIOUS_LINK_FUNCTION*, uintptr_t);
struct blockchain_link* blockchain_link_previous_link(struct blockchain_link*, int, size_t);
unsigned int blockchain_link_get_next_bits(struct blockchain_link*, struct blockchain_link*, unsigned int next_block_timestamp);
void blockchain_link_free(struct blockchain_link*);
struct block_locator* blockchain_link_block_locator(struct blockchain_link*);

#endif /* __BLOCKCHAIN_H */
