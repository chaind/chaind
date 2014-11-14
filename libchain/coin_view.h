#ifndef __COIN_VIEW_H
#define __COIN_VIEW_H

struct coin_view;
struct transaction;
struct transaction_output_reference;

typedef int (COIN_VIEW_DESTROY_FUNCTION)(struct coin_view*, void*);
typedef int (COIN_VIEW_FIND_BLOCKCHAIN_TRANSACTION_FUNCTION)(struct coin_view*, void*, unsigned char* hash, struct transaction** tx, size_t* height);
typedef int (COIN_VIEW_FIND_BLOCKCHAIN_SPEND_FUNCTION)(struct coin_view*, void*, struct transaction_output_reference*, struct transaction** tx);
typedef int (COIN_VIEW_APPLY_TRANSACTION_FUNCTION)(struct coin_view*, void*, struct transaction*, size_t block_height);

struct coin_view* coin_view_new(
    COIN_VIEW_DESTROY_FUNCTION*,
    COIN_VIEW_FIND_BLOCKCHAIN_TRANSACTION_FUNCTION*,
    COIN_VIEW_FIND_BLOCKCHAIN_SPEND_FUNCTION*,
    COIN_VIEW_APPLY_TRANSACTION_FUNCTION*,
    void* userdata;
);

void coin_view_destroy(struct coin_view*);

int coin_view_find_blockchain_transaction(struct coin_view* cv, unsigned char* hash, struct transaction**, size_t* height);
int coin_view_find_blockchain_spend(struct coin_view* cv, struct transaction_output_reference*, struct transaction**);
int coin_view_apply_transaction(struct coin_view* cv, struct transaction*, size_t block_height);

#endif /* __COIN_VIEW_H */
