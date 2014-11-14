#ifndef __DATABASE_ADDRESS_H
#define __DATABASE_ADDRESS_H

struct _bson_t;
typedef struct _bson_t bson_t;

struct database;
struct network_address;

int database_create_peer_address_indexes(struct database* db);
int database_add_peer_address(struct database* db, struct network_address*);

int database_has_peer_addresses(struct database*);
int database_get_random_peer_address(struct database*, struct network_address*);

void network_address_bson(struct network_address const*, bson_t*);
void network_address_from_bson(bson_t const*, struct network_address*);

#endif /* __DATABASE_ADDRESS_H */
