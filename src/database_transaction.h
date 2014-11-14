#ifndef __DATABASE_TRANSACTION_H
#define __DATABASE_TRANSACTION_H

struct _bson_t;
typedef struct _bson_t bson_t;

struct database;
struct transaction;

int database_create_transaction_indexes(struct database*);
int database_add_orphan_transaction(struct database*, unsigned char const*, struct transaction const*);
int database_find_blockchain_transaction(struct database*, unsigned char* hash, size_t max_height, struct transaction** tx, size_t* height);
int database_find_blockchain_spend(struct database*, struct transaction_output_reference*, size_t start_height, size_t max_height, struct transaction** tx);
int database_has_transaction(struct database*, unsigned char const*);

// TODO: move these to libchain/transaction.c ?
void transaction_bson(struct transaction const*, bson_t* out);
struct transaction* transaction_from_bson(bson_t const*);

#endif /* __DATABASE_TRANSACTION_H */
