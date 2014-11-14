#ifndef __DATABASE_H
#define __DATABASE_H

struct database;
struct inv;

struct database* database_open(char const* server, int port, int use_ssl, char const* dbname);
void database_close(struct database*);

int database_has_inv(struct database*, struct inv const*);

#include "database_address.h"
#include "database_blockchain.h"
#include "database_transaction.h"

#endif /* __DATABASE_H */
