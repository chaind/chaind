#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <libchain/libchain.h>
#include <mongoc.h>

#include "database.h"

struct database {
    mongoc_client_t* client;
    char* dbname;
};

static inline char const* database_name(struct database* db)
{
    return db->dbname;
}

struct database* database_open(char const* server, int port, int use_ssl, char const* dbname)
{
    char url[256];
    snprintf(url, sizeof(url), "mongodb://%s:%d/", server, port);

    struct database* db = (struct database*)malloc(sizeof(struct database));
    zero(db);

    mongoc_init();
    db->client = mongoc_client_new(url);
    db->dbname = strdup(dbname);

    database_create_transaction_indexes(db);
    database_create_blockchain_indexes(db);

    return db;
}

void database_close(struct database* db)
{
    free(db->dbname);
    mongoc_client_destroy(db->client);
    free(db);
}

int database_has_inv(struct database* db, struct inv const* inv)
{
    int result = 0;

    // TODO check cache
    // check db
    mongoc_collection_t* collection = NULL;
    
    switch(inv->type) {
    case INV_TYPE_TX:
        return database_has_transaction(db, inv->hash);
    case INV_TYPE_BLOCK:
        return database_has_block(db, inv->hash);
        collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");
        break;
    case INV_TYPE_ERROR:
        assert(0);
        break;
    }

    // Convert the transaction to a bson document
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)inv->hash, 32);

    // Setup an empty projection so that the query returns less data
    bson_t* proj = bson_new();

    // Find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, proj, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
    }

    bson_t const* doc;
    if(mongoc_cursor_next(cursor, &doc) != 0) {
        result = 1;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(proj);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return result;
}

#include "database_address.c"
#include "database_blockchain.c"
#include "database_transaction.c"

