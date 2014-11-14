#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <libchain/libchain.h>
#include <mongoc.h>

#include "database.h"
#include "database_address.h"

int database_create_peer_address_indexes(struct database* db)
{
    bson_t* keys;
    mongoc_index_opt_t opt;
    bson_error_t error;

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "peer_addresses");

    // peer_addresses.r [unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "r", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 1;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (peer_addresses.r)\n");
        }

        bson_destroy(keys);
    }

    // (peer_addresses.network_address.{type,ipvx,port}) [unique]
    {
        keys = bson_new();
        BSON_APPEND_INT32(keys, "network_address.type", 1);
        BSON_APPEND_INT32(keys, "network_address.ipvx", 1);
        BSON_APPEND_INT32(keys, "network_address.port", 1);

        mongoc_index_opt_init(&opt);
        opt.unique = 1;

        if(mongoc_collection_create_index(collection, keys, &opt, &error) == 0) {
            printf("index creation error (peer_addresses.network_address)\n");
        }

        bson_destroy(keys);
    }

    mongoc_collection_destroy(collection);
    return 0;
}

int database_add_peer_address(struct database* db, struct network_address* address)
{
    int result = 0;

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "peer_addresses");
    
    bson_t* doc = bson_new();
    bson_t* network_address_doc = bson_new();

    // Convert the network address to a bson document
    BSON_APPEND_DOCUMENT_BEGIN(doc, "network_address", network_address_doc);
    network_address_bson(address, network_address_doc);
    bson_append_document_end(doc, network_address_doc);

    // Give it a new id
    bson_oid_t oid;
    bson_oid_init(&oid, NULL);
    BSON_APPEND_OID(doc, "_id", &oid);

    // The random number is used for selecting random documents later
    BSON_APPEND_INT32(doc, "r", rand());

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
        result = -1;
    }

    bson_destroy(doc);
    mongoc_collection_destroy(collection);
    return result;
}

int database_has_peer_addresses(struct database* db)
{
    return database_get_random_peer_address(db, NULL) != 0;
}

int database_get_random_peer_address(struct database* db, struct network_address* out)
{
    int result = 0;
    int selection_r = rand();

    mongoc_collection_t* collection = mongoc_client_get_collection(db->client, database_name(db), "peer_addresses");
    
    for(int i = 0; i < 2 && result == 0; i++) {
        bson_t* query = bson_new();

        bson_t* subquery = bson_new();
        BSON_APPEND_DOCUMENT_BEGIN(query, "$query", subquery);

        bson_t* gte_doc = bson_new();
        BSON_APPEND_DOCUMENT_BEGIN(subquery, "r", gte_doc);
        if(i == 0) {
            BSON_APPEND_INT32(gte_doc, "$gte", selection_r);
        } else {
            BSON_APPEND_INT32(gte_doc, "$lte", selection_r);
        }
        bson_append_document_end(subquery, gte_doc);
        bson_append_document_end(query, subquery);

        bson_t* orderby = bson_new();
        BSON_APPEND_DOCUMENT_BEGIN(query, "$orderby", orderby);
        BSON_APPEND_INT32(orderby, "r", (i == 0) ? 1 : -1);
        bson_append_document_end(query, orderby);

        // The final document looks like: {"$query": {"r": {"$gte": selection_r}}, {"$orderby": {"r": 1}}}
        // or                             {"$query": {"r": {"$lte": selection_r}}, {"$orderby": {"r": -1}}}

        // Perform find with null projection and limit 1
        mongoc_cursor_t* cursor = mongoc_collection_find(collection, MONGOC_QUERY_NONE, 0, 1, 0, query, NULL, NULL);

        bson_error_t error;
        if(cursor == NULL || mongoc_cursor_error(cursor, &error)) {
            printf("MongoDB error: %s\n", (cursor == NULL) ? "NULL cursor" : error.message);
            result = -1;
        } else {
            bson_t const* doc;
            while(mongoc_cursor_next(cursor, &doc) != 0) {
                if(out != NULL) network_address_from_bson(doc, out);
                result = 1;
                break;
            }
        }

        if(cursor != NULL) mongoc_cursor_destroy(cursor);
        bson_destroy(gte_doc);
        bson_destroy(orderby);
        bson_destroy(subquery);
        bson_destroy(query);
    }

    mongoc_collection_destroy(collection);
    return result;
}

void network_address_bson(struct network_address const* address, bson_t* out)
{
    BSON_APPEND_INT32(out, "type", (int)address->type);

    if(address->type == NETWORK_ADDRESS_TYPE_IPV4) {
        size_t size = sizeof(address->ipv4);
        unsigned char* buf = (unsigned char*)alloca(size);
        memcpy(buf, &address->ipv4, size);
        BSON_APPEND_BINARY(out, "ipvx", BSON_SUBTYPE_BINARY, (uint8_t*)buf, size);
    } else if(address->type == NETWORK_ADDRESS_TYPE_IPV6) {
        size_t size = sizeof(address->ipv6);
        unsigned char* buf = (unsigned char*)alloca(size);
        memcpy(buf, &address->ipv6, size);
        BSON_APPEND_BINARY(out, "ipvx", BSON_SUBTYPE_BINARY, (uint8_t*)buf, size);
    }

    BSON_APPEND_INT32(out, "port", (int)address->sin_port);
}

void network_address_from_bson(bson_t const* doc, struct network_address* out)
{
    bson_iter_t iter;
    bson_iter_t subiter;

    // If the network address document isn't found, that's weird
    if(!bson_iter_init_find(&iter, doc, "network_address") || !BSON_ITER_HOLDS_DOCUMENT(&iter)) goto error;

    // Load the network_address document
    bson_t network_address_doc;
    uint32_t network_address_doc_length;
    uint8_t const* network_address_doc_data;
    bson_iter_document(&iter, &network_address_doc_length, &network_address_doc_data);
    bson_init_static(&network_address_doc, network_address_doc_data, network_address_doc_length);

    if(!bson_iter_init_find(&subiter, &network_address_doc, "type") || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    out->type = (enum NETWORK_ADDRESS_TYPE)bson_iter_int32(&subiter);

    uint8_t const* ipvx;
    uint32_t ipvx_size;

    if(!bson_iter_init_find(&subiter, &network_address_doc, "ipvx") || !BSON_ITER_HOLDS_BINARY(&subiter)) goto error;
    bson_iter_binary(&subiter, BSON_SUBTYPE_BINARY, &ipvx_size, &ipvx);

    if(out->type == NETWORK_ADDRESS_TYPE_IPV4) {
        size_t size = sizeof(out->ipv4);
        assert(ipvx_size == (uint32_t)size);
        memcpy(&out->ipv4, ipvx, size);
    } else if(out->type == NETWORK_ADDRESS_TYPE_IPV6) {
        size_t size = sizeof(out->ipv6);
        assert(ipvx_size == (uint32_t)size);
        memcpy(&out->ipv6, ipvx, size);
    }

    if(!bson_iter_init_find(&subiter, &network_address_doc, "port") || !BSON_ITER_HOLDS_INT32(&subiter)) goto error;
    out->sin_port = (unsigned short)(bson_iter_int32(&subiter) & 0x0000FFFF);
    return;
error:
    assert(0);
}
