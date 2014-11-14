#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <libchain/libchain.h>
#include <mongoc.h>

#include "database.h"
#include "database_blockchain.h"

// we need transaction_from_bson()
#include "database_transaction.h"

int database_create_blockchain_indexes(struct database* db)
{
    bson_t* keys;
    mongoc_index_opt_t opt;
    bson_error_t error;

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // blocks.hash [unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "hash", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 1;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (blocks.hash)\n");
        }

        bson_destroy(keys);
    }

    // blocks.header.previous_block_hash [non-unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "header.previous_block_hash", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 0;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (blocks.header.previous_block_hash)\n");
        }

        bson_destroy(keys);
    }

    // blocks.height [non-unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "height", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 0;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (blocks.height)\n");
        }

        bson_destroy(keys);
    }

    // blocks.transactions.hash [non-unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "transactions.hash", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 0;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (blocks.transactions.hash)\n");
        }

        bson_destroy(keys);
    }

    mongoc_collection_destroy(collection);
    return 0;
}

struct block* database_get_block(struct database* db, unsigned char* block_hash)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Build a query doc
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)block_hash, 32);

    // Perform find with null projection to get everything
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, NULL, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return NULL;
    }

    struct block* block = NULL;
    struct vector transaction_hashes;
    vector_init(&transaction_hashes);

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        block = block_from_bson(doc, &transaction_hashes);
        break;
    }

    if(block == NULL) {
        printf("MongoDB error: block not found\n");
        return NULL;
    }

    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);

    // This block has no transactions in it, so we need to get the actual transactions from the database that
    collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

    for(size_t i = 0; i < vector_count(&transaction_hashes); i++) {
        unsigned char* tx_hash = (unsigned char*)vector_get(&transaction_hashes, i);

        // Set the hash
        bson_reinit(query);
        BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)tx_hash, 32);

        // Perform find with null projection to get everything
        cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, NULL, NULL);

        if(mongoc_cursor_next(cursor, &doc) == 0) {
            printf("MongoDB error: transaction referenced by block isn't in database\n");
            return NULL;
        }

        struct transaction* tx = transaction_from_bson(doc);
        block_add_transaction(block, tx);

        mongoc_cursor_destroy(cursor);
        free(tx_hash);
    }

    vector_free(&transaction_hashes);
    bson_destroy(query);

    return block;
}

int database_has_block(struct database* db, unsigned char const* hash)
{
    int result = 0;

    // TODO check cache
    // check db
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Convert the transaction to a bson document
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

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

int database_connect_block(struct database* db, unsigned char* block_hash, struct blockchain_link* link)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Build a query doc
    bson_t* find_doc = bson_new();
    BSON_APPEND_BINARY(find_doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)block_hash, 32);

    // Get the transaction set and mark them in the block as necessary
    bson_t* proj_doc = bson_new();
    BSON_APPEND_INT32(proj_doc, "transactions", 1);
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, find_doc, proj_doc, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return -1;
    }

    struct vector transaction_hashes;
    vector_init(&transaction_hashes);

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        bson_iter_t iter;
        bson_iter_t subiter;

        if(!bson_iter_init_find(&iter, doc, "transactions") || !BSON_ITER_HOLDS_ARRAY(&iter)) {
            return -1;
        }

        // Extract the array into a bson doc
        bson_t transactions_doc;
        uint32_t doc_length;
        uint8_t const* doc_data;
        bson_iter_array(&iter, &doc_length, &doc_data);
        bson_init_static(&transactions_doc, doc_data, doc_length);

        size_t tx_index = 0;
        char key[9];
        for(;;) {
            bson_snprintf(key, sizeof(key), "%u", (unsigned int)tx_index);
            key[sizeof(key) - 1] = '\0';

            // If the array key isn't found, then we reached the end of the array
            if(!bson_iter_init_find(&subiter, &transactions_doc, key)) break;

            // If it's not a document, then there's an error
            if(!BSON_ITER_HOLDS_DOCUMENT(&subiter)) {
                return -1;
            }

            bson_t element_doc;
            uint32_t element_doc_length;
            uint8_t const* element_doc_data;
            bson_iter_document(&subiter, &element_doc_length, &element_doc_data);
            bson_init_static(&element_doc, element_doc_data, element_doc_length);

            bson_iter_t elementiter;
            if(!bson_iter_init_find(&elementiter, &element_doc, "hash") || !BSON_ITER_HOLDS_BINARY(&elementiter)) {
                return -1;
            }

            uint8_t const* tx_hash;
            uint32_t tx_hash_size;
            bson_iter_binary(&elementiter, BSON_SUBTYPE_BINARY, &tx_hash_size, &tx_hash);
            assert(tx_hash_size == 32);

            vector_add(&transaction_hashes, (uintptr_t)memdup(tx_hash, tx_hash_size));

            tx_index++;
        }

        break;
    }

    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

    bson_t* set_doc = bson_new();
    bson_t* update = bson_new();

    int is_main = blockchain_link_main(link);
    size_t height = blockchain_link_height(link);

    size_t num_transaction_hashes = vector_count(&transaction_hashes);
    for(size_t i = 0; i < num_transaction_hashes; i++) {
        unsigned char* tx_hash = (unsigned char*)vector_get(&transaction_hashes, i);

        bson_reinit(find_doc);
        BSON_APPEND_BINARY(find_doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)tx_hash, 32);

        bson_reinit(update);
        bson_reinit(set_doc);
        BSON_APPEND_DOCUMENT_BEGIN(set_doc, "$set", update);
        BSON_APPEND_INT32(update, "height", is_main == 0 ? -1 : height);
        bson_append_document_end(set_doc, update);

        // Perform update
        if(mongoc_collection_update(collection, MONGOC_UPDATE_NONE, find_doc, set_doc, NULL, &error) == 0) {
            printf("MongoDB update error: %s\n", error.message);
        }

        free(tx_hash);
    }

    vector_free(&transaction_hashes);
    mongoc_collection_destroy(collection);
    collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Reinit block hash
    bson_reinit(find_doc);
    BSON_APPEND_BINARY(find_doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)block_hash, 32);

    // Build the update
    bson_reinit(update);
    bson_reinit(set_doc);
    BSON_APPEND_DOCUMENT_BEGIN(set_doc, "$set", update);
    BSON_APPEND_BOOL(update, "connected", 1);
    BSON_APPEND_BOOL(update, "main", is_main);
    BSON_APPEND_INT32(update, "height", height);

    mpz_t work;
    mpz_init(work);
    blockchain_link_work(link, work);

    size_t s = mpz_sizeinbase(work, 16);
    char* buf = (char*)alloca(sizeof(char) * (s + 2));
    mpz_get_str(buf, 16, work);
    BSON_APPEND_UTF8(update, "work", buf);
    bson_append_document_end(set_doc, update);
    mpz_clear(work);

    // Perform update
    if(mongoc_collection_update(collection, MONGOC_UPDATE_NONE, find_doc, set_doc, NULL, &error) == 0) {
        printf("MongoDB update error: %s\n", error.message);
    }

    bson_destroy(update);
    bson_destroy(set_doc);
    bson_destroy(find_doc);
    mongoc_collection_destroy(collection);
    return 0;
}

int database_add_disconnected_block(struct database* db, unsigned char const* hash, struct block* block)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Convert the block to a bson document
    bson_t* doc = bson_new();
    block_bson(block, doc);

    // Set the hash
    BSON_APPEND_BINARY(doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

    // Starts as disconnected
    BSON_APPEND_BOOL(doc, "connected", 0);
    BSON_APPEND_BOOL(doc, "main", 0);
    BSON_APPEND_INT32(doc, "height", -1);

    // Work is computed from the header
    mpz_t work;
    mpz_init(work);
    block_header_work(block_header(block), work);

    uint32_t size = mpz_sizeinbase(work, 16);
    char* buf = alloca(sizeof(char) * (size + 2));
    mpz_get_str(buf, 16, work);
    BSON_APPEND_UTF8(doc, "work", buf);
    mpz_clear(work);

    // Median time past for disconnected blocks is just the same as the timestamp
    BSON_APPEND_INT32(doc, "median_time_past", (int)block_header_timestamp(block_header(block)));

    // Give it a new id
    bson_oid_t oid;
    bson_oid_init(&oid, NULL);
    BSON_APPEND_OID(doc, "_id", &oid);

#if 0
    // Print json
    char* str = bson_as_json(doc, NULL);
    printf("%s\n", str);
    bson_free(str);
#endif

    // Perform insert
    bson_error_t error;
    if(mongoc_collection_insert(collection, MONGOC_INSERT_NONE, doc, NULL, &error) == 0) {
        printf("MongoDB error: %s\n", error.message);
    }

    bson_destroy(doc);
    mongoc_collection_destroy(collection);
    return 0;
}

static bson_t* get_blockchain_link_projection(void)
{
    // Build a projection
    bson_t* proj = bson_new();

    // Pull out the header + chain info
    BSON_APPEND_INT32(proj, "header", 1);
    BSON_APPEND_INT32(proj, "main", 1);
    BSON_APPEND_INT32(proj, "connected", 1);
    BSON_APPEND_INT32(proj, "height", 1);
    BSON_APPEND_INT32(proj, "work", 1);

    return proj;
}

static struct blockchain_link* database_get_previous_blockchain_link(struct blockchain_link* link, uintptr_t data, int by_count, size_t count)
{
    struct database* db = (struct database*)data;

    if(by_count == 0) {
        unsigned char hash[32];
        block_header_previous_block_hash(blockchain_link_block_header(link), hash);
        if(memcmp(hash, HASH_ZERO, 32) == 0) return NULL;
        return database_get_blockchain_link(db, hash);
    } else {
        assert(count <= blockchain_link_height(link));
        size_t height = blockchain_link_height(link) - count;
        return database_get_main_blockchain_link_at_height(db, height);
    }
}

struct blockchain_link* database_get_blockchain_link(struct database* db, unsigned char* block_hash)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Build a query doc
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)block_hash, 32);

    bson_t* proj = get_blockchain_link_projection();

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, proj, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return NULL;
    }

    struct blockchain_link* link = NULL;

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        link = blockchain_link_from_bson(doc);
        blockchain_link_set_previous_link(link, database_get_previous_blockchain_link, (uintptr_t)db);
        break;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(proj);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return link;
}

struct blockchain_link* database_get_main_blockchain_link_at_height(struct database* db, size_t height)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Build a query doc
    bson_t* query = bson_new();

    // Set the height and main chain flag
    BSON_APPEND_INT32(query, "height", (int)height);
    BSON_APPEND_BOOL(query, "main", 1);

    // Build a projection
    bson_t* proj = get_blockchain_link_projection();

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, proj, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return NULL;
    }

    struct blockchain_link* link = NULL;

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        link = blockchain_link_from_bson(doc);
        blockchain_link_set_previous_link(link, database_get_previous_blockchain_link, (uintptr_t)db);
        break;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(proj);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return link;
}

struct blockchain_link* database_get_best_blockchain_link(struct database* db)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // "query" needs to be in $query if we specify a sort order
    bson_t* query = bson_new();

    bson_t* subquery = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(query, "$query", subquery);
    BSON_APPEND_BOOL(subquery, "main", 1);
    BSON_APPEND_BOOL(subquery, "connected", 1);
    bson_append_document_end(query, subquery);

    bson_t* orderby = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(query, "$orderby", orderby);
    BSON_APPEND_INT32(orderby, "height", -1);
    bson_append_document_end(query, orderby);

    // Build a projection
    bson_t* proj = get_blockchain_link_projection();

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, proj, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return NULL;
    }

    struct blockchain_link* link = NULL;

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        link = blockchain_link_from_bson(doc);
        blockchain_link_set_previous_link(link, database_get_previous_blockchain_link, (uintptr_t)db);
        break;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(subquery);
    bson_destroy(orderby);
    bson_destroy(proj);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return link;
}

int database_find_blockchain_links_by_previous_block_hash(struct database* db, unsigned char* previous_block_hash, struct vector* result)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");
    vector_init(result);

    // Build a query doc
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "header.previous_block_hash", BSON_SUBTYPE_BINARY, (uint8_t*)previous_block_hash, 32);

    // Build a projection
    bson_t* proj = get_blockchain_link_projection();

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 0, 0, query, proj, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return -1;
    }

    bson_t const* doc;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        struct blockchain_link* link = blockchain_link_from_bson(doc);
        blockchain_link_set_previous_link(link, database_get_previous_blockchain_link, (uintptr_t)db);
        assert(link != NULL);
        vector_add(result, (uintptr_t)link);
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(proj);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return 0;
}

static int compare_uint(const void* a, const void* b)
{
    unsigned int ai = (unsigned int)(*((uintptr_t*)a) & 0xFFFFFFFF);
    unsigned int bi = (unsigned int)(*((uintptr_t*)b) & 0xFFFFFFFF);
    if(ai < bi) return -1;
    if(ai > bi) return  1;
    return 0;
}

int database_set_median_time_past(struct database* db, unsigned char* block_hash, size_t nblocks)
{
    struct vector times;
    vector_init(&times);

    unsigned char current_hash[32];
    memcpy(current_hash, block_hash, 32);

    for(size_t i = 0; i < nblocks; i++) {
        struct blockchain_link* link = database_get_blockchain_link(db, current_hash);

        // If a chain of blocks doesn't exist -- different than reaching genesis -- then
        // return error;
        if(link == NULL) goto error;

        struct block_header* header = blockchain_link_block_header(link);

        vector_add(&times, (uintptr_t)block_header_timestamp(header));
        block_header_previous_block_hash(header, current_hash);
        blockchain_link_free(link);

        if(memcmp(current_hash, HASH_ZERO, 32) == 0) break;
    }

    size_t num_times = vector_count(&times);
    assert(num_times != 0);

    qsort(vector_data(&times), (size_t)num_times, sizeof(uintptr_t), compare_uint);
    unsigned int median_time_past = (unsigned int)vector_get(&times, num_times / 2);
    vector_free(&times);

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "blocks");

    // Build a query doc
    bson_t* find_doc = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(find_doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)block_hash, 32);

    // Build the update
    bson_t* set_doc = bson_new();
    bson_t* update = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(set_doc, "$set", update);
    BSON_APPEND_INT32(update, "median_time_past", median_time_past);
    bson_append_document_end(set_doc, update);

    // Perform update
    bson_error_t error;
    if(mongoc_collection_update(collection, MONGOC_UPDATE_NONE, find_doc, set_doc, NULL, &error) == 0) {
        printf("MongoDB update error: %s\n", error.message);
    }

    bson_destroy(update);
    bson_destroy(set_doc);
    bson_destroy(find_doc);
    mongoc_collection_destroy(collection);
    return 0;
error:
    vector_free(&times);
    return -1;
}

void block_bson(struct block* block, bson_t* out)
{
    char key[9];
    struct block_header* header = block_header(block);

    bson_t* header_doc = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(out, "header", header_doc);

    // Version
    BSON_APPEND_INT32(header_doc, "version", (int)block_header_version(header));

    // Previous Block Hash
    unsigned char hash[32];
    block_header_previous_block_hash(header, hash);
    BSON_APPEND_BINARY(header_doc, "previous_block_hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

    // Merkle Root 
    unsigned char mr[32];
    block_header_merkle_root(header, mr);
    BSON_APPEND_BINARY(header_doc, "merkle_root", BSON_SUBTYPE_BINARY, (uint8_t*)mr, 32);

    // Timestamp
    BSON_APPEND_INT32(header_doc, "timestamp", (int)block_header_timestamp(header));

    // Difficulty
    BSON_APPEND_INT32(header_doc, "bits", (int)block_header_bits(header));

    // Nonce
    BSON_APPEND_INT32(header_doc, "nonce", (int)block_header_nonce(header));

    // Done with "header"
    bson_append_document_end(out, header_doc);

    // Transactions (hashes only)
    bson_t* tx_list = bson_new();
    BSON_APPEND_ARRAY_BEGIN(out, "transactions", tx_list);
    size_t num_transactions = block_num_transactions(block);
    for(size_t i = 0; i < num_transactions; i++) {
        struct transaction* tx = block_transaction(block, i);
        
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)i);
        key[sizeof(key) - 1] = '\0';

        bson_t* member = bson_new();
        bson_append_document_begin(tx_list, key, -1, member);

        // Transaction hash
        transaction_hash(tx, hash);
        BSON_APPEND_BINARY(member, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

        bson_append_document_end(tx_list, member);
    }
    bson_append_array_end(out, tx_list);
}

struct block* block_from_bson(bson_t const* doc, vector* transaction_hashes)
{
    bson_iter_t iter;
    bson_iter_t subiter;
    uint8_t const* data;
    uint32_t size;
    struct block* block = block_new();
    struct block_header* header = block_header(block);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.version", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_version(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.previous_block_hash", &subiter) 
       || !BSON_ITER_HOLDS_BINARY(&subiter)) goto error;
    bson_iter_binary(&subiter, BSON_SUBTYPE_BINARY, &size, &data);
    assert(size == 32);
    block_header_set_previous_block_hash(header, data);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.merkle_root", &subiter) 
       || !BSON_ITER_HOLDS_BINARY(&subiter)) goto error;
    bson_iter_binary(&subiter, BSON_SUBTYPE_BINARY, &size, &data);
    assert(size == 32);
    block_header_set_merkle_root(header, data);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.timestamp", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_timestamp(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.bits", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_bits(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.nonce", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_nonce(header, bson_iter_int32(&subiter));

    if(!bson_iter_init_find(&iter, doc, "transactions") || !BSON_ITER_HOLDS_ARRAY(&iter)) goto error;
    bson_t transactions_doc;
    uint32_t doc_length;
    uint8_t const* doc_data;
    bson_iter_array(&iter, &doc_length, &doc_data);
    bson_init_static(&transactions_doc, doc_data, doc_length);

    size_t tx_index = 0;
    char key[9];
    for(;;) {
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)tx_index);
        key[sizeof(key) - 1] = '\0';

        // If the array key isn't found, then we reached the end of the array
        if(!bson_iter_init_find(&subiter, &transactions_doc, key)) break;

        // If it's not a document, then there's an error
        if(!BSON_ITER_HOLDS_DOCUMENT(&subiter)) goto error;

        bson_t element_doc;
        uint32_t element_doc_length;
        uint8_t const* element_doc_data;
        bson_iter_document(&subiter, &element_doc_length, &element_doc_data);
        bson_init_static(&element_doc, element_doc_data, element_doc_length);

        bson_iter_t elementiter;
        if(!bson_iter_init_find(&elementiter, &element_doc, "hash") || !BSON_ITER_HOLDS_BINARY(&elementiter)) goto error;

        uint8_t const* tx_hash;
        uint32_t tx_hash_size;
        bson_iter_binary(&elementiter, BSON_SUBTYPE_BINARY, &tx_hash_size, &tx_hash);
        assert(tx_hash_size == 32);

        vector_add(transaction_hashes, (uintptr_t)memdup(tx_hash, tx_hash_size));

        tx_index++;
    }

    return block;
error:
    assert(0);
    return NULL;
}

struct blockchain_link* blockchain_link_from_bson(bson_t const* doc)
{
    bson_iter_t iter;
    bson_iter_t subiter;
    uint8_t const* data;
    uint32_t size;
    struct blockchain_link* link = blockchain_link_new();
    struct block_header* header = blockchain_link_block_header(link);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.version", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_version(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.previous_block_hash", &subiter) 
       || !BSON_ITER_HOLDS_BINARY(&subiter)) goto error;
    bson_iter_binary(&subiter, BSON_SUBTYPE_BINARY, &size, &data);
    assert(size == 32);
    block_header_set_previous_block_hash(header, data);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.merkle_root", &subiter) 
       || !BSON_ITER_HOLDS_BINARY(&subiter)) goto error;
    bson_iter_binary(&subiter, BSON_SUBTYPE_BINARY, &size, &data);
    assert(size == 32);
    block_header_set_merkle_root(header, data);

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.timestamp", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_timestamp(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.bits", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_bits(header, bson_iter_int32(&subiter));

    if(!bson_iter_init(&iter, doc) 
       || !bson_iter_find_descendant(&iter, "header.nonce", &subiter) 
       || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    block_header_set_nonce(header, bson_iter_int32(&subiter));

    if(!bson_iter_init_find(&iter, doc, "main") || !BSON_ITER_HOLDS_BOOL(&iter)) goto error;
    blockchain_link_set_main(link, (int)bson_iter_bool(&iter));

    if(!bson_iter_init_find(&iter, doc, "connected") || !BSON_ITER_HOLDS_BOOL(&iter)) goto error;
    blockchain_link_set_connected(link, (int)bson_iter_bool(&iter));

    if(!bson_iter_init_find(&iter, doc, "height") || !BSON_ITER_HOLDS_INT32(&iter)) goto error;
    blockchain_link_set_height(link, (int)bson_iter_int32(&iter));

    if(!bson_iter_init_find(&iter, doc, "work") || !BSON_ITER_HOLDS_UTF8(&iter)) goto error;
    char const* workstr = bson_iter_utf8(&iter, &size);
    mpz_t work;
    mpz_init_set_str(work, workstr, 16);
    blockchain_link_set_work(link, work);
    mpz_clear(work);

    return link;
error:
    assert(0);
    blockchain_link_free(link);
    return NULL;
}


