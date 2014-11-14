#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <libchain/libchain.h>
#include <mongoc.h>

#include "database.h"
#include "database_transaction.h"

int database_create_transaction_indexes(struct database* db)
{
    bson_t* keys;
    mongoc_index_opt_t opt;
    bson_error_t error;

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

    // transactions.hash
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "hash", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 1;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (transaction.hash)\n");
        }

        bson_destroy(keys);
    }

    // (transaction.inputs.output_reference.hash, transaction.inputs.output_reference.index) [non-unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "inputs.output_reference.hash", 1);
        BSON_APPEND_INT32(keys, "inputs.output_reference.index", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 0;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (inputs.output_reference)\n");
        }

        bson_destroy(keys);
    }

    mongoc_collection_destroy(collection);
    return 0;
}

int database_has_transaction(struct database* db, unsigned char const* hash)
{
    int result = 0;

    // TODO check cache
    // check db
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

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

int database_add_orphan_transaction(struct database* db, unsigned char const* hash, struct transaction const* tx)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");
    
    // Convert the transaction to a bson document
    bson_t* doc = bson_new();
    transaction_bson(tx, doc);

    // Set the hash
    BSON_APPEND_BINARY(doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

    // Give it a new id
    bson_oid_t oid;
    bson_oid_init(&oid, NULL);
    BSON_APPEND_OID(doc, "_id", &oid);

    // Orphan -> height = -1
    BSON_APPEND_INT32(doc, "height", -1);

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

int database_find_blockchain_transaction(struct database* db, unsigned char* hash, size_t max_height, struct transaction** tx, size_t* height)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

    // Build a query doc
    bson_t* query = bson_new();

    // Set the hash
    BSON_APPEND_BINARY(query, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);

    // Force the height to be valid (on the main chain)
    bson_t* height_doc = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(query, "height", height_doc);
    BSON_APPEND_INT32(height_doc, "$lte", (int)max_height);
    BSON_APPEND_INT32(height_doc, "$gte", 0);
    bson_append_document_end(query, height_doc);

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return -1;
    }

    bson_t const* doc;
    int found = 0;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        if(height != NULL) {
            bson_iter_t iter;
            if(!bson_iter_init_find(&iter, doc, "height") || !BSON_ITER_HOLDS_INT32(&iter)) {
                printf("MongoDB error: tx doesn't have height!\n");
                return -1;
            }
            *height = (size_t)bson_iter_int32(&iter);
        }

        if(tx != NULL) {
            *tx = transaction_from_bson(doc);
        }

        found = 1;
        break;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(height_doc);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return found;
}

// Find the spend of a specified output_reference within a given blockheight range (main chain only)
// if found, load tx and the input that spends it
int database_find_blockchain_spend(struct database* db, struct transaction_output_reference* output_reference, size_t start_height, size_t max_height, struct transaction** tx)
{
    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "transactions");

    // Build a query doc
    bson_t* query = bson_new();

    // Build a query that tries to find where this output_reference is spent
    unsigned char hash[32];
    transaction_output_reference_hash(output_reference, hash);

    bson_t* output_reference_doc = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(query, "inputs.output_reference", output_reference_doc);
    BSON_APPEND_BINARY(output_reference_doc, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)hash, 32);
    BSON_APPEND_INT32(output_reference_doc, "index", transaction_output_reference_index(output_reference));
    bson_append_document_end(query, output_reference_doc);

    // Force the height to be valid
    bson_t* height_doc = bson_new();
    BSON_APPEND_DOCUMENT_BEGIN(query, "height", height_doc);
    BSON_APPEND_INT32(height_doc, "$lte", (int)max_height);
    BSON_APPEND_INT32(height_doc, "$gte", start_height);
    bson_append_document_end(query, height_doc);

    // Perform find
    mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);

    bson_error_t error;
    if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
        printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
        return -1;
    }

    bson_t const* doc;
    int found = 0;
    while(mongoc_cursor_next(cursor, &doc) != 0) {
        if(tx != NULL) {
            *tx = transaction_from_bson(doc);
        }

        found = 1;
        break;
    }

    mongoc_cursor_destroy(cursor);
    bson_destroy(height_doc);
    bson_destroy(output_reference_doc);
    bson_destroy(query);
    mongoc_collection_destroy(collection);
    return found;
}

void transaction_bson(struct transaction const* tx, bson_t* out)
{
    char key[9];

    bson_t* input_list = bson_new();

    // Version
    BSON_APPEND_INT32(out, "version", (int)transaction_version(tx));

    // Inputs
    BSON_APPEND_ARRAY_BEGIN(out, "inputs", input_list);
    size_t num_inputs = transaction_num_inputs(tx);
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)i);
        key[sizeof(key) - 1] = '\0';

        bson_t* member = bson_new();
        bson_append_document_begin(input_list, key, -1, member);

        // Output Reference
        struct transaction_output_reference* output_reference = transaction_input_output_reference(input);
        unsigned char prevout_hash[32];
        transaction_output_reference_hash(output_reference, prevout_hash);
        bson_t* prevout = bson_new();
        bson_append_document_begin(member, "output_reference", -1, prevout);
        BSON_APPEND_BINARY(prevout, "hash", BSON_SUBTYPE_BINARY, (uint8_t*)prevout_hash, 32);
        BSON_APPEND_INT32(prevout, "index", transaction_output_reference_index(output_reference));
        bson_append_document_end(member, prevout);

        // Script
        struct script* script = transaction_input_script(input);
        BSON_APPEND_BINARY(member, "script", BSON_SUBTYPE_BINARY, (uint8_t*)script_data(script), script_size(script));

        // Sequence
        BSON_APPEND_INT32(member, "sequence", transaction_input_sequence(input));

        bson_append_document_end(input_list, member);
    }
    bson_append_array_end(out, input_list);

    // Outputs
    bson_t* output_list = bson_new();
    BSON_APPEND_ARRAY_BEGIN(out, "outputs", output_list);
    size_t num_outputs = transaction_num_outputs(tx);
    for(size_t i = 0; i < num_outputs; i++) {
        struct transaction_output* output = transaction_output(tx, i);
        
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)i);
        key[sizeof(key) - 1] = '\0';

        bson_t* member = bson_new();
        bson_append_document_begin(output_list, key, -1, member);

        // Value
        BSON_APPEND_INT64(member, "value", transaction_output_value(output));

        // Script
        struct script* script = transaction_output_script(output);
        BSON_APPEND_BINARY(member, "script", BSON_SUBTYPE_BINARY, (uint8_t*)script_data(script), script_size(script));

        bson_append_document_end(output_list, member);
    }
    bson_append_array_end(out, output_list);

    // Lock time
    BSON_APPEND_INT32(out, "lock_time", (int)transaction_lock_time(tx));
}

struct transaction* transaction_from_bson(bson_t const* doc)
{
    char key[9];
    bson_iter_t iter;
    bson_iter_t subiter;
    struct transaction* tx = transaction_new();

    if(!bson_iter_init_find(&iter, doc, "version") || !BSON_ITER_HOLDS_INT32(&iter)) goto error;
    transaction_set_version(tx, bson_iter_int32(&iter));

    // Read Inputs
    if(!bson_iter_init_find(&iter, doc, "inputs") || !BSON_ITER_HOLDS_ARRAY(&iter)) goto error;

    uint32_t inputs_doc_length;
    uint8_t const* inputs_doc_data;
    bson_iter_array(&iter, &inputs_doc_length, &inputs_doc_data);

    bson_t inputs_doc;
    bson_init_static(&inputs_doc, inputs_doc_data, inputs_doc_length);

    size_t index = 0;
    for(;;) {
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)index);
        key[sizeof(key) - 1] = '\0';

        // If the array key isn't found, then we reached the end of the array
        if(!bson_iter_init_find(&subiter, &inputs_doc, key)) break;

        // If it's not a document, then there's an error
        if(!BSON_ITER_HOLDS_DOCUMENT(&subiter)) goto error;

        struct transaction_input* input = transaction_input_new();
        struct transaction_output_reference* output_reference = transaction_input_output_reference(input);

        // Load the input document
        bson_t element_doc;
        uint32_t element_doc_length;
        uint8_t const* element_doc_data;
        bson_iter_document(&subiter, &element_doc_length, &element_doc_data);
        bson_init_static(&element_doc, element_doc_data, element_doc_length);

        bson_iter_t elementiter;

        // Output reference
        if(!bson_iter_init_find(&elementiter, &element_doc, "output_reference") || !BSON_ITER_HOLDS_DOCUMENT(&elementiter)) goto error;
        bson_t output_reference_doc;
        uint32_t output_reference_doc_length;
        uint8_t const* output_reference_doc_data;
        bson_iter_document(&elementiter, &output_reference_doc_length, &output_reference_doc_data);
        bson_init_static(&output_reference_doc, output_reference_doc_data, output_reference_doc_length);

        bson_iter_t output_reference_iter;

        uint8_t const* hash;
        uint32_t hash_size;

        if(!bson_iter_init_find(&output_reference_iter, &output_reference_doc, "hash") || !BSON_ITER_HOLDS_BINARY(&output_reference_iter)) goto error;
        bson_iter_binary(&output_reference_iter, BSON_SUBTYPE_BINARY, &hash_size, &hash);
        assert(hash_size == 32);
        transaction_output_reference_set_hash(output_reference, (unsigned char const*)hash);

        if(!bson_iter_init_find(&output_reference_iter, &output_reference_doc, "index") || !BSON_ITER_HOLDS_INT32(&output_reference_iter)) goto error;
        transaction_output_reference_set_index(output_reference, bson_iter_int32(&output_reference_iter));

        // Script
        if(!bson_iter_init_find(&elementiter, &element_doc, "script") || !BSON_ITER_HOLDS_BINARY(&elementiter)) goto error;
        uint32_t script_size;
        uint8_t const* script_data;
        bson_iter_binary(&elementiter, BSON_SUBTYPE_BINARY, &script_size, &script_data);
        struct script* script;
        size_t script_size_result;
        script_size_result = unserialize_script((unsigned char const*)script_data, script_size, &script, script_size);
        assert(script_size_result == script_size);
        transaction_input_set_script(input, script);

        // Sequence
        if(!bson_iter_init_find(&elementiter, &element_doc, "sequence") || !BSON_ITER_HOLDS_INT32(&elementiter)) goto error;
        transaction_input_set_sequence(input, bson_iter_int32(&elementiter));

        transaction_add_input(tx, input);
        index += 1;
    }

    // Read Outputs
    if(!bson_iter_init_find(&iter, doc, "outputs") || !BSON_ITER_HOLDS_ARRAY(&iter)) goto error;

    uint32_t outputs_doc_length;
    uint8_t const* outputs_doc_data;
    bson_iter_array(&iter, &outputs_doc_length, &outputs_doc_data);

    bson_t outputs_doc;
    bson_init_static(&outputs_doc, outputs_doc_data, outputs_doc_length);

    index = 0;
    for(;;) {
        bson_snprintf(key, sizeof(key), "%u", (unsigned int)index);
        key[sizeof(key) - 1] = '\0';

        // If the array key isn't found, then we reached the end of the array
        if(!bson_iter_init_find(&subiter, &outputs_doc, key)) break;

        // If it's not a document, then there's an error
        if(!BSON_ITER_HOLDS_DOCUMENT(&subiter)) goto error;

        struct transaction_output* output = transaction_output_new();

        // Load the output document
        bson_t element_doc;
        uint32_t element_doc_length;
        uint8_t const* element_doc_data;
        bson_iter_document(&subiter, &element_doc_length, &element_doc_data);
        bson_init_static(&element_doc, element_doc_data, element_doc_length);

        bson_iter_t elementiter;

        // Value
        if(!bson_iter_init_find(&elementiter, &element_doc, "value") || !BSON_ITER_HOLDS_INT64(&elementiter)) goto error;
        transaction_output_set_value(output, bson_iter_int64(&elementiter));

        // Script
        if(!bson_iter_init_find(&elementiter, &element_doc, "script") || !BSON_ITER_HOLDS_BINARY(&elementiter)) goto error;
        uint32_t script_size;
        uint8_t const* script_data;
        bson_iter_binary(&elementiter, BSON_SUBTYPE_BINARY, &script_size, &script_data);
        struct script* script;
        size_t script_size_result;
        script_size_result = unserialize_script((unsigned char const*)script_data, script_size, &script, script_size);
        assert(script_size_result == script_size);
        transaction_output_set_script(output, script);

        transaction_add_output(tx, output);
        index += 1;
    }

    if(!bson_iter_init_find(&iter, doc, "lock_time") || !BSON_ITER_HOLDS_INT32(&iter)) goto error;
    transaction_set_lock_time(tx, bson_iter_int32(&iter));

    return tx;
error:
    return NULL;
}
