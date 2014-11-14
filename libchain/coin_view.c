#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>

#include "coin_view.h"
#include "util.h"

struct coin_view {
    COIN_VIEW_DESTROY_FUNCTION* destroy_function;
    COIN_VIEW_FIND_BLOCKCHAIN_TRANSACTION_FUNCTION* find_blockchain_transaction;
    COIN_VIEW_FIND_BLOCKCHAIN_SPEND_FUNCTION* find_blockchain_spend;
    COIN_VIEW_APPLY_TRANSACTION_FUNCTION* apply_transaction;

    void* userdata;
};

struct coin_view* coin_view_new(
    COIN_VIEW_DESTROY_FUNCTION* destroy_function,
    COIN_VIEW_FIND_BLOCKCHAIN_TRANSACTION_FUNCTION* find_blockchain_transaction,
    COIN_VIEW_FIND_BLOCKCHAIN_SPEND_FUNCTION* find_blockchain_spend,
    COIN_VIEW_APPLY_TRANSACTION_FUNCTION* apply_transaction,
    void* userdata
)
{
    struct coin_view* cv = (struct coin_view*)malloc(sizeof(struct coin_view));
    zero(cv);

    cv->destroy_function = destroy_function;
    cv->find_blockchain_transaction = find_blockchain_transaction;
    cv->find_blockchain_spend = find_blockchain_spend;
    cv->apply_transaction = apply_transaction;
    cv->userdata = userdata;

    return cv;
}

void coin_view_destroy(struct coin_view* cv)
{
    cv->destroy_function(cv, cv->userdata);
    free(cv);
}

int coin_view_find_blockchain_transaction(struct coin_view* cv, unsigned char* hash, struct transaction** tx, size_t* height)
{
    return cv->find_blockchain_transaction(cv, cv->userdata, hash, tx, height);
}

int coin_view_find_blockchain_spend(struct coin_view* cv, struct transaction_output_reference* output_reference, struct transaction** tx)
{
    return cv->find_blockchain_spend(cv, cv->userdata, output_reference, tx);
}

int coin_view_apply_transaction(struct coin_view* cv, struct transaction* tx, size_t block_height)
{
    return cv->apply_transaction(cv, cv->userdata, tx, block_height);
}
