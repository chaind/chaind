#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libchain/libchain.h>
#include <Judy.h>

#include "chaind.h"
#include "config.h"
#include "database.h"
#include "dbus.h"
#include "logging.h"
#include "memory_pool.h"
#include "network_manager.h"

struct chaind {
    struct config* config;
    struct database* database;
    struct dbus* dbus;
    struct memory_pool* memory_pool;
    struct network_manager* network_manager;
    size_t blockchain_target_size;
    struct blockchain_link* best_blockchain_link;
    int request_exit;
};

struct chaind_coin_view {
    struct chaind* state;
    void*  transactions;
    size_t next_transaction_id;
    void*  transaction_id_by_hash;
    void*  transaction_id_by_output_reference;
};

struct chaind_coin_view_transaction {
    struct transaction* transaction;
    size_t height;
};

static struct blockchain_link* get_best_blockchain_link(struct database*);
static void check_block_database(struct chaind*);
static void add_transactions_from_block_to_database(struct database*, struct inv const*, struct block*);
static int is_block_version_majority(struct database*, int, size_t, size_t, unsigned char*);
static void set_best_blockchain_link(struct chaind*, unsigned char*);

struct chaind* chaind_init(struct config* cfg)
{
    crypto_init();
    srand(time(NULL));

    struct chaind* state = (struct chaind*)malloc(sizeof(struct chaind));
    zero(state);
    state->config = cfg;

    state->database = database_open(cfg->mongodb.hostname, cfg->mongodb.port, 0, cfg->mongodb.database);
    if(state->database == NULL) goto error;

    state->memory_pool = memory_pool_create(1ULL << 20, 1ULL << 30); // TODO compute better values based on memory availability?
    if(state->memory_pool == NULL) goto error;

    state->best_blockchain_link = get_best_blockchain_link(state->database);
    if(state->best_blockchain_link == NULL) goto error;

    state->dbus = dbus_start_service(state);
    if(state->dbus == NULL) goto error;

    check_block_database(state);

    state->network_manager = network_manager_create(state);
    if(state->network_manager == NULL) goto error;
    network_manager_listen(state->network_manager);
    
    return state;
error:
    chaind_deinit(state);
    free(state);
    return NULL;
}

int chaind_deinit(struct chaind* state)
{
    if(state->network_manager != NULL) network_manager_destroy(state->network_manager);
    if(state->dbus != NULL) dbus_destroy_service(state->dbus);
    if(state->memory_pool != NULL) memory_pool_destroy(state->memory_pool);
    if(state->best_blockchain_link != NULL) blockchain_link_free(state->best_blockchain_link);
    if(state->database != NULL) database_close(state->database);
    crypto_deinit();
    return 0;
}

int chaind_update(struct chaind* state)
{
    int r = 0;

    if((r = dbus_update(state->dbus)) < 0) return r;

    if((r = network_manager_update(state->network_manager)) < 0) return r;

    return state->request_exit;
}

void chaind_request_exit(struct chaind* state)
{
    state->request_exit = 1;
}

struct blockchain_link* chaind_best_blockchain_link(struct chaind* state)
{
    return state->best_blockchain_link;
}

struct config* chaind_config(struct chaind* state)
{
    return state->config;
}

struct database* chaind_database(struct chaind* state)
{
    return state->database;
}

struct memory_pool* chaind_memory_pool(struct chaind* state)
{
    return state->memory_pool;
}

static struct blockchain_link* get_best_blockchain_link(struct database* db)
{
    struct blockchain_link* link = blockchain_link_new();

    // Verify the genesis block
    struct block* gb = block_genesis();
    struct inv genesis_inv;
    genesis_inv.type = INV_TYPE_BLOCK;
    block_header_hash(block_header(gb), genesis_inv.hash);
    bytes_to_hexstring(genesis_inv.hash, 32, hash_str, 1);
    log_debug("Genesis block hash: %s", hash_str);
    assert(strcmp(hash_str, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") == 0);

    unsigned char calc_merkle_root[32];
    int v = block_calculate_merkle_root(gb, calc_merkle_root);
    assert(v == 0);

    unsigned char merkle_root[32];
    block_header_merkle_root(block_header(gb), merkle_root);
    assert(memcmp(merkle_root, calc_merkle_root, 32) == 0);

    // Put the genesis data into the database
    if(database_has_inv(db, &genesis_inv) == 0) {
        // Add it as orphan
        add_transactions_from_block_to_database(db, &genesis_inv, gb);
        database_add_disconnected_block(db, genesis_inv.hash, gb);

        // Connect it
        struct blockchain_link* link = database_get_blockchain_link(db, genesis_inv.hash);
        blockchain_link_set_main(link, 1);
        blockchain_link_set_connected(link, 1);
        blockchain_link_set_height(link, 0);

        mpz_t work;
        mpz_init(work);
        block_header_work(block_header(gb), work);
        blockchain_link_set_work(link, work);
        
        database_connect_block(db, genesis_inv.hash, link);

        mpz_clear(work);
        blockchain_link_free(link);
    }

#if 0
    link = database_get_best_blockchain_link(db);
    unsigned char hashs[32];
    block_header_hash(blockchain_link_block_header(link), hashs);

    size_t howmany = 1;
    uint64_t start = microtime();
    for(size_t i = 0; i < howmany; i++) {
        struct block_locator* loc = blockchain_link_block_locator(link);
        block_locator_free(loc);
    }
    uint64_t end = microtime();
    printf("%llu us for %d calls, %f avg\n", end - start, (int)howmany, ((double)(end-start))/(double)howmany);
#endif

    // Get blockchain height in the database
    link = database_get_best_blockchain_link(db);
    assert(link != NULL);
    {
        unsigned char hash[32];
        block_header_hash(blockchain_link_block_header(link), hash);
        bytes_to_hexstring(hash, 32, s, 1);
        log_debug("best blockchain is %s (height = %d)", s, blockchain_link_height(link));
    }

    return link;
}

static void check_block_database(struct chaind* state)
{
    // it's possible that handle_block never completed updating to a new best chain
    // we should retry connecting here?
    unsigned char best_blockchain_link_hash[32];
    block_header_hash(blockchain_link_block_header(state->best_blockchain_link), best_blockchain_link_hash);
        
    #if 0
    {
        struct inv inv;
        inv.type = INV_TYPE_BLOCK;
        block_header_hash(blockchain_link_block_header(state->best_blockchain_link), inv.hash);
        struct block* block = database_get_block(state->database, inv.hash);
        chaind_handle_block(state, &inv, block);
        return;
    }
    #endif

    struct vector result;
    if(database_find_blockchain_links_by_previous_block_hash(state->database, best_blockchain_link_hash, &result) < 0) {
        // interla db error
        assert(0);
        return;
    }

    size_t count = vector_count(&result);
    for(size_t i = 0; i < count; i++) {
        struct blockchain_link* link = (struct blockchain_link*)vector_get(&result, i);

        struct inv inv;
        inv.type = INV_TYPE_BLOCK;
        block_header_hash(blockchain_link_block_header(link), inv.hash);

#if 0
        {
            bytes_to_hexstring(inv.hash, 32, s, 1);
            log_debug("trying to extend best block by %s", s);
        }
#endif

        struct block* block = database_get_block(state->database, inv.hash);
        assert(block != NULL);

        chaind_handle_block(state, &inv, block);

        block_free(block);
        blockchain_link_free(link);
    }

    vector_free(&result);
}    

static int destroy_coin_view(struct coin_view* cv, void* userdata)
{
    struct chaind_coin_view* ccv = (struct chaind_coin_view*)userdata;

    // free applied transactions
    Word_t index = 0;
    struct transaction** ptx;
    JLF(ptx, ccv->transactions, index);
    while(ptx != NULL) {
        transaction_free(*ptx);
        JLN(ptx, ccv->transactions, index);
    }

    Word_t wrc;
    JLFA(wrc, ccv->transactions);

    int rc;
    JHSFA(rc, ccv->transaction_id_by_hash);
    JHSFA(rc, ccv->transaction_id_by_output_reference);

    free(ccv);
    return 0;
}

static int find_blockchain_transaction(struct coin_view* cv, void* userdata, unsigned char* hash, struct transaction** tx, size_t* height)
{
    struct chaind_coin_view* ccv = (struct chaind_coin_view*)userdata;
    struct chaind* state = ccv->state;

    // check the memory pool of transactions first, if it doesn't exist check the database
    Word_t* pindex;
    JHSG(pindex, ccv->transaction_id_by_hash, hash, 32);

    if(pindex != NULL) {
        Word_t index = *pindex;
        struct chaind_coin_view_transaction** pcvtx;

        JLG(pcvtx, ccv->transactions, index);
        assert_pointer(pcvtx);

        if(height != NULL) *height = (*pcvtx)->height;

        if(tx != NULL) *tx = transaction_clone((*pcvtx)->transaction);

        return 1;
    }

    return database_find_blockchain_transaction(state->database, hash, blockchain_link_height(state->best_blockchain_link), tx, height);
}

static int find_blockchain_spend(struct coin_view* cv, void* userdata, struct transaction_output_reference* output_reference, struct transaction** tx)
{
    struct chaind_coin_view* ccv = (struct chaind_coin_view*)userdata;
    struct chaind* state = ccv->state;

    // look for the output_reference in a list of known spent outputs
    size_t output_reference_size = serialize_transaction_output_reference(NULL, output_reference);
    unsigned char* buffer = (unsigned char*)alloca(sizeof(unsigned char) * output_reference_size);
    serialize_transaction_output_reference(buffer, output_reference);

    Word_t* pindex;
    JHSG(pindex, ccv->transaction_id_by_output_reference, buffer, output_reference_size);

    if(pindex != NULL) {
        if(tx != NULL) {
            Word_t index = *pindex;
            struct chaind_coin_view_transaction** pcvtx;
            JLG(pcvtx, ccv->transactions, index);
            assert_pointer(pcvtx);
            *tx = transaction_clone((*pcvtx)->transaction);
        }

        return 1;
    }

    // otherwise look in the database for the spend
    return database_find_blockchain_spend(state->database, output_reference, 0, blockchain_link_height(state->best_blockchain_link), tx);
}

static int apply_transaction(struct coin_view* cv, void* userdata, struct transaction* tx, size_t block_height)
{
    struct chaind_coin_view* ccv = (struct chaind_coin_view*)userdata;

    struct transaction* clone = transaction_clone(tx);
    unsigned char hash[32];
    transaction_hash(clone, hash);

    // wrap the tx with some metadata
    struct chaind_coin_view_transaction* cvtx = (struct chaind_coin_view_transaction*)malloc(sizeof(struct chaind_coin_view_transaction));
    cvtx->transaction = clone;
    cvtx->height = block_height;

    // put this tx in a memory pool of transactions
    Word_t index = (Word_t)ccv->next_transaction_id;
    struct chaind_coin_view_transaction** pcvtx;
    JLI(pcvtx, ccv->transactions, index);
    assert_pointer(pcvtx);
    *pcvtx = cvtx;
    ccv->next_transaction_id += 1;

    // in order to find this tx by hash, we need a mapping of hash -> index
    Word_t* pindex;
    JHSI(pindex, ccv->transaction_id_by_hash, hash, 32);
    assert_pointer(pindex);
    *pindex = index;

    // for each input, add the output_reference to a memory pool of spent objects so that we can find
    // spent outputs caused by this tx
    if(transaction_is_coinbase(clone) != 1) {
        size_t num_inputs = transaction_num_inputs(clone);
        size_t output_reference_size = serialize_transaction_output_reference(NULL, transaction_input_output_reference(transaction_input(clone, 0))); // all txns have at least 1 input
        unsigned char* buffer = (unsigned char*)alloca(sizeof(unsigned char) * output_reference_size);

        for(size_t i = 0; i < num_inputs; i++) {
            struct transaction_input* input = transaction_input(clone, i);
            struct transaction_output_reference* output_reference = transaction_input_output_reference(input);
            size_t r = serialize_transaction_output_reference(buffer, output_reference);
            assert(r == output_reference_size);

            JHSI(pindex, ccv->transaction_id_by_output_reference, buffer, output_reference_size);
            assert_pointer(pindex);
            *pindex = index;
        }
    }

    return 0;
}

struct coin_view* chaind_coin_view_new(struct chaind* state)
{
    struct chaind_coin_view* ccv = (struct chaind_coin_view*)malloc(sizeof(struct chaind_coin_view));
    zero(ccv);

    ccv->state = state;

    return coin_view_new(
        &destroy_coin_view,
        &find_blockchain_transaction,
        &find_blockchain_spend,
        &apply_transaction,
        (void*)ccv
    );
}

static void add_transactions_from_block_to_database(struct database* db, struct inv const* inv, struct block* block)
{
    size_t num_transactions = block_num_transactions(block);

    struct inv tx_inv;
    tx_inv.type = INV_TYPE_TX;

    for(size_t i = 0; i < num_transactions; i++) {
        struct transaction* tx = block_transaction(block, i);
        transaction_hash(tx, tx_inv.hash);

        // Make sure the tx is in the db already
        if(database_has_inv(db, &tx_inv) == 0) {
            database_add_orphan_transaction(db, tx_inv.hash, tx);
        }
    }
}

// I considered if I should maintain meta-data about block majorities in the database, but decided not to do it
// 1) because it requires keeping track of multiple links and thus another 64+x bytes for every block, which honestly
// isn't *that* bad, and 2) block version majorities are only checked once for every block when they're connected
// and after the initial sync doing this once every 10 minutes isn't exactly terrible
static int is_block_version_majority(struct database* db, int min_version, size_t requirement, size_t out_of, unsigned char* start_block_hash)
{
    size_t found = 0;

    unsigned char current_hash[32];
    memcpy(current_hash, start_block_hash, 32);

    for(size_t i = 0; i < out_of; i++) {
        struct blockchain_link* link = database_get_blockchain_link(db, current_hash);
        struct block_header* header = blockchain_link_block_header(link);

        if(block_header_version(header) >= min_version) found += 1;
        block_header_previous_block_hash(header, current_hash);

        blockchain_link_free(link);

        if(memcmp(current_hash, HASH_ZERO, 32) == 0) break;
    }

    return (found >= requirement) ? 1 : 0;
}

static int verify_transaction_inputs(struct coin_view* cv, struct transaction* tx, size_t new_height, uint64_t* fees)
{
    if(transaction_is_coinbase(tx)) return 1;

    size_t num_inputs = transaction_num_inputs(tx);
    uint64_t total_input = 0;

    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        struct transaction_output_reference* output_reference = transaction_input_output_reference(input);
        unsigned char output_reference_hash[32];
        transaction_output_reference_hash(output_reference, output_reference_hash);
    
        struct transaction* cvtx = NULL;
        size_t height = 0;
        if(coin_view_find_blockchain_transaction(cv, output_reference_hash, &cvtx, &height) != 1) {
            assert(0); // TODO: transaction input not found
            return 0;
        }

        if(transaction_output_reference_index(output_reference) >= transaction_num_outputs(cvtx)) {
            transaction_free(cvtx);
            assert(0); // TODO Bad index
            return 0;
        }

        // Check coinbase age
        if(transaction_is_coinbase(cvtx) && (new_height - height) < BLOCK_COINBASE_SPENDING_AGE) {
            transaction_free(cvtx);
            assert(0); // TODO coinbase hasn't matured
            return 0;
        }

        
#if 0   // TODO slow. use a cache?
        // Check if output is spent
        if(coin_view_find_blockchain_spend(cv, output_reference, NULL) != 0) {
            transaction_free(cvtx);
            assert(0); // TODO input already spent
            return 0;
        }
#elif defined(DEBUG)
        log_warning("coin_view_find_blockchain_spend disabled");
#endif

        total_input += transaction_output_value(transaction_output(cvtx, transaction_output_reference_index(output_reference)));
        if(total_input > TOTAL_COINS) {
            transaction_free(cvtx);
            assert(0); // TODO too much input
            return 0;
        }

        transaction_free(cvtx);
    }

    uint64_t total_output = transaction_total_output_value(tx);
    if(total_input < total_output) {
        assert(0); // TODO not enough inputs
        return 0;
    }

    *fees = total_input - total_output;
    if(*fees > TOTAL_COINS) {
        assert(0); // TODO probably won't ever happen
        return 0;
    }

#if 1
    // the above are the inexpensive checks, and here is the script signature checking bit. we
    // will never use checkpoints so we must run signature checking on every tx. sorry.
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        struct transaction_output_reference* output_reference = transaction_input_output_reference(input);
        unsigned char output_reference_hash[32];
        transaction_output_reference_hash(output_reference, output_reference_hash);

        struct transaction* cvtx = NULL;
        coin_view_find_blockchain_transaction(cv, output_reference_hash, &cvtx, NULL);
        assert(cvtx != NULL); // It was found once above, shouldn't fail here.

        struct transaction_output* output = transaction_output(cvtx, transaction_output_reference_index(output_reference));

#if 0
        struct script* output_script = transaction_output_script(output);
        size_t output_script_hex_size = script_size(output_script) * 2 + 1;
        char* b = (char*)alloca(sizeof(char) * output_script_hex_size);
        memset(b, 0, output_script_hex_size);
        __bytes_to_hexstring(script_data(output_script), script_size(output_script), b, output_script_hex_size, 0);
        printf("* verifying input #%d :: %s\n", (int)i, b);
#endif

        int script_result;
        if((script_result = script_verify(transaction_output_script(output), tx, i)) < 0) {
            // The transaction 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192 in block 170060 is an invalid
            // spend technically, but is allowed because embedded P2SH scripts wasn't evaluated until a later date.
            if(new_height == 170060 && transaction_hash_equals_string(tx, "6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192") == 1) {
                // allow
                script_result = 1;
            } else {
                transaction_free(cvtx);
                assert(0); // TODO bad script
                return 0;
            }
        }

        // script result of 0 means the script executed fine but the result was 0
        if(script_result != 1) {
            transaction_free(cvtx);
            assert(0); // TODO bad script signature / invalid spend script
            return 0;
        }

        transaction_free(cvtx);
    }
#endif
    return 1;
}

static void connect_block(struct chaind* state, struct blockchain_link* link_to_connect)
{
    unsigned char best_hash[32];
    block_header_hash(blockchain_link_block_header(state->best_blockchain_link), best_hash);

    unsigned char previous_block_hash[32];
    block_header_previous_block_hash(blockchain_link_block_header(link_to_connect), previous_block_hash);

    assert(memcmp(best_hash, previous_block_hash, 32) == 0);

    unsigned char connect_hash[32];
    block_header_hash(blockchain_link_block_header(link_to_connect), connect_hash);

    struct block* block = database_get_block(state->database, connect_hash);
    assert(block != NULL);

    size_t num_transactions = block_num_transactions(block);

    // BIP30 - enforce no duplicate transaction hashes except on two blocks 91842 and 91880
    if(!((blockchain_link_height(link_to_connect) == 91842 && memcmp(connect_hash, BIP30_BLOCK_91842_HASH, 32) == 0)
      || (blockchain_link_height(link_to_connect) == 91880 && memcmp(connect_hash, BIP30_BLOCK_91880_HASH, 32) == 0))) {
        for(size_t i = 0; i < num_transactions; i++) {
            struct transaction* tx = block_transaction(block, i);
            unsigned char hash[32];
            transaction_hash(tx, hash);

            size_t height = 0;
            struct transaction* dbtx = NULL;
            if(database_find_blockchain_transaction(state->database, hash, blockchain_link_height(link_to_connect) - 1, &dbtx, &height) == 1) {
                // This tx existed in the blockchain previously, the only way we can allow this block to connect 
                // is if there's a spend for every output in this transaction between height and 
                // blockchain_link_height(link_to_connect)-1
                struct transaction_input* tmp = transaction_input_new();
                struct transaction_output_reference* output_reference = transaction_input_output_reference(tmp);
                transaction_output_reference_set_hash(output_reference, hash);

                size_t num_outputs = transaction_num_outputs(dbtx);
                for(size_t i = 0; i < num_outputs; i++) {
                    transaction_output_reference_set_index(output_reference, i);
                    if(database_find_blockchain_spend(state->database, output_reference, height, blockchain_link_height(link_to_connect) - 1, NULL) != 1) {
                        // Block error!
                        // TODO: undo everything and go back to the old chain :(
                        log_warning("block contains duplicate hash of a transaction that isn't fully spent");
                        assert(0);
                        return;
                    }
                }

                transaction_input_free(tmp);
                transaction_free(dbtx);
            }
        }
    }

    size_t block_height = blockchain_link_height(link_to_connect);
    unsigned int block_time = block_header_timestamp(block_header(block));
    unsigned int total_sigops = 0;
    uint64_t total_fees = 0;

    struct coin_view* cv = chaind_coin_view_new(state);

    // All transactions have to be verified now
    for(size_t i = 0; i < num_transactions; i++) {
        struct transaction* tx = block_transaction(block, i);

#if 1
        {
            unsigned char hash[32];
            transaction_hash(tx, hash);
            bytes_to_hexstring(hash, 32, s, 1);
            log_debug("... verifying transaction #%d :: %s", (int)i, s);
        }
#endif

        total_sigops += transaction_legacy_sigop_count(tx);
        if(total_sigops > BLOCK_MAX_SIGOPS) {
            assert(0); // TODO: tx uses too many sigops
            return;
        }

        if(i > 0) {
            uint64_t fees = 0;

            // Coinbase transactions don't need their inputs verified
            if(verify_transaction_inputs(cv, tx, block_height, &fees) != 1) {
                assert(0); // TODO transaction inputs aren't available/spendable
                return;
            }

            total_fees += fees;
            if(total_fees > TOTAL_COINS) {
                assert(0); // TODO block has too many fees
                return;
            }

            // Count P2SH sigops
            if(block_time >= BIP16_SWITCH_TIME) {
                unsigned int p2sh_sigops = transaction_p2sh_sigop_count(tx, cv);
                total_sigops += p2sh_sigops;
                
                if (total_sigops > BLOCK_MAX_SIGOPS) {
                    assert(0); // TODO: tx uses too many sigops
                    return;
                }
            }
        }

        coin_view_apply_transaction(cv, tx, block_height);
    }

    // Mark the block as connected and in the main chain
    blockchain_link_set_main(link_to_connect, 1);
    database_connect_block(state->database, connect_hash, link_to_connect);

    // publish publish the fact that this block was added to the main chain
    dbus_block_connected(state->dbus, connect_hash, block_height, block_num_transactions(block));
    
    block_free(block);
}

static void disconnect_block(struct chaind* state, struct blockchain_link* link_to_disconnect)
{
    unsigned char best_hash[32];
    block_header_hash(blockchain_link_block_header(state->best_blockchain_link), best_hash);

    unsigned char disconnect_hash[32];
    block_header_hash(blockchain_link_block_header(link_to_disconnect), disconnect_hash);

    assert(memcmp(best_hash, disconnect_hash, 32) == 0);

    // Mark the block as connected but not in the main chain
    blockchain_link_set_main(link_to_disconnect, 0);
    database_connect_block(state->database, disconnect_hash, link_to_disconnect);

    // TODO publish publish the fact that this block was removed from the main chain
}

static void set_best_blockchain_link(struct chaind* state, unsigned char* connected_block_hash)
{
    struct blockchain_link* link = database_get_blockchain_link(state->database, connected_block_hash);
    assert(link != NULL);
    assert(blockchain_link_connected(link) == 1);
    assert(blockchain_link_main(link) == 0);

    mpz_t best_work;
    mpz_t new_work;

    mpz_init(best_work);
    mpz_init(new_work);

    blockchain_link_work(state->best_blockchain_link, best_work);
    blockchain_link_work(link, new_work);

    // New chain must have more work
    int cmp = mpz_cmp(new_work, best_work);
    mpz_clear(best_work);
    mpz_clear(new_work);

    if(cmp <= 0) {
        blockchain_link_free(link);
        return;
    }

    // 'link' is the new best chain
    struct blockchain_link* old_best_blockchain_link = state->best_blockchain_link;
    struct blockchain_link* new_best_blockchain_link = link;

    // The first goal is to find the common ancestor between the two links (there has to be one, all the way up to the genesis if necessary)
    // Along the walk up, the old chain's blocks can be disconnected
    // At this point old and new chain are of the same height
    unsigned char old_hash[32];
    block_header_hash(blockchain_link_block_header(old_best_blockchain_link), old_hash);

    unsigned char new_hash[32];
    block_header_hash(blockchain_link_block_header(new_best_blockchain_link), new_hash);

    struct vector blockchain_links_to_connect;
    vector_init(&blockchain_links_to_connect);

    while(memcmp(old_hash, new_hash, 32) != 0) {

        // If the old chain is longer (or equal), pop a block
        if(blockchain_link_height(old_best_blockchain_link) >= blockchain_link_height(new_best_blockchain_link)) {
            // Disconnect block forces us to only be able to disconnect the head of the best chain
            disconnect_block(state, old_best_blockchain_link);

#if 1
            bytes_to_hexstring(old_hash, 32, s, 1);
            log_info("--> removed from blockchain %s at height %d", s, blockchain_link_height(old_best_blockchain_link));
#endif

            // So we free that link and proceed up the chain
            state->best_blockchain_link = blockchain_link_previous_link(old_best_blockchain_link, 0, 0);
            blockchain_link_free(old_best_blockchain_link);
            old_best_blockchain_link = state->best_blockchain_link;
            block_header_hash(blockchain_link_block_header(old_best_blockchain_link), old_hash);
            continue;
        }

        // There's no way the chains can be equal length (the old would be moved up already)
        if(blockchain_link_height(new_best_blockchain_link) > blockchain_link_height(old_best_blockchain_link)) {
            // We don't "connect_block" this one yet because we're working backwards
            vector_add(&blockchain_links_to_connect, (uintptr_t)new_best_blockchain_link);

            // Proceed up the chain
            new_best_blockchain_link = blockchain_link_previous_link(new_best_blockchain_link, 0, 0);
            block_header_hash(blockchain_link_block_header(new_best_blockchain_link), new_hash);
            continue;
        }
    }

    // old_best_blockchain_link and new_best_blockchain_link are now pointing to the common ancestor, but we don't
    // need to keep new_best_blockchain_link around any more.
    blockchain_link_free(new_best_blockchain_link);

    // At this point we've disconnected everything in the old chain, now we just walk through the new chain and connect them
    for(ssize_t i = vector_count(&blockchain_links_to_connect) - 1; i >= 0; i--) {
        struct blockchain_link* link_to_connect = (struct blockchain_link*)vector_get(&blockchain_links_to_connect, (size_t)i);
        
        // Verify this block is connecting to the right place
        unsigned char previous_block_hash[32];
        block_header_previous_block_hash(blockchain_link_block_header(link_to_connect), previous_block_hash);
        assert(memcmp(old_hash, previous_block_hash, 32) == 0);

#if 1
        bytes_to_hexstring(new_hash, 32, s, 1);
        log_info("--> connecting %s to blockchain at height %d", s, blockchain_link_height(link_to_connect));
#endif

        // Connect the block in the database
        connect_block(state, link_to_connect);

        // Update our best chain pointer
        blockchain_link_free(state->best_blockchain_link);
        state->best_blockchain_link = link_to_connect;
        blockchain_link_set_main(state->best_blockchain_link, 1);

        block_header_hash(blockchain_link_block_header(link_to_connect), new_hash);
        memcpy(old_hash, new_hash, 32);

    }

    // state->best_blockchain_link is now pointing to the head of the new branch
    vector_free(&blockchain_links_to_connect);

    return;
}

static int check_transaction(struct transaction* tx)
{
    size_t num_inputs = transaction_num_inputs(tx);
    if(num_inputs == 0) {
        log_notice("transaction is invalid: zero inputs");
        return 0;
    }

    size_t num_outputs = transaction_num_outputs(tx);
    if(num_outputs == 0) {
        log_notice("transaction is invalid: zero outputs");
        return 0;
    }

    // Not really sure why Bitcoin Core checks against the block size here...
    // TODO adjust this downward using a different metric
    if(serialize_transaction(NULL, tx) > BLOCK_MAX_SERIALIZE_SIZE) {
        log_notice("transaction is invalid: zero outputs");
        return 0;
    }

    // Verify output amounts
    uint64_t total_output = 0;
    for(size_t i = 0; i < num_outputs; i++) {
        uint64_t output_value = transaction_output_value(transaction_output(tx, i));
        if(output_value > TOTAL_COINS) {
            log_notice("transaction is invalid: output %d pays too much", (int)i);
            return 0;
        }

        total_output += output_value;
        if(total_output > TOTAL_COINS) {
            log_notice("transaction is invalid: transaction pays too much");
            return 0;
        }
    }

    // non-coinbase transactions should have non-null output references
    int is_coinbase = transaction_is_coinbase(tx);

    // and coinbase transactions should have a proper script size
    if(is_coinbase) {
        struct script* script = transaction_input_script(transaction_input(tx, 0));
        if(script_size(script) < 2 || script_size(script) > 100) {
            log_notice("transaction is invalid: coinbase script has invalid size");
            return 0;
        }
    }

    // check for duplicate inputs
    size_t output_reference_size = serialize_transaction_output_reference(NULL, transaction_input_output_reference(transaction_input(tx, 0)));
    unsigned char* buf = (unsigned char*)alloca(sizeof(unsigned char) * output_reference_size);

    void* input_set = NULL;
    int rc;
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_output_reference* output_reference = transaction_input_output_reference(transaction_input(tx, i));
        serialize_transaction_output_reference(buf, output_reference);

        if(is_coinbase != 1 && transaction_output_reference_is_null(output_reference) == 1) {
            log_notice("transaction is invalid: non-null output reference found");
            JHSFA(rc, input_set);
            return 0;
        }

        Word_t* pi;
        JHSI(pi, input_set, (uint8_t*)buf, output_reference_size);
        assert(pi != NULL);

        if((*pi) != 0) { // Found a duplicate
            log_notice("transaction is invalid: duplicate input");
            JHSFA(rc, input_set);
            return 0;
        }

        (*pi) = 1;
    }

    JHSFA(rc, input_set);

    return 1;
}

static int check_block(struct block* block)
{
    size_t num_transactions = block_num_transactions(block);
    unsigned int sigop_count = 0;

    // Must have at least one transaction
    if(num_transactions == 0) {
        log_notice("block is invalid: zero transactions in block");
        return -1;
    }

    // Block must serialize to within the limit
    if(serialize_block(NULL, block) > BLOCK_MAX_SERIALIZE_SIZE) {
        log_notice("block is invalid: too big");
        return -2;
    }

    // check the blocks proof of work. we can't verify the difficulty and timestamp 
    // until it connects to a previous block
    if(block_header_valid(block_header(block)) == 0) {
        log_notice("block is invalid: bad proof-of-work");
        return -3;
    }

    // First tx must be a coinbase
    struct transaction* tx = block_transaction(block, 0);
    if(transaction_is_coinbase(tx) != 1 || check_transaction(tx) != 1) {
        log_notice("block is invalid: transaction 0 isn't valid coinbase");
        return -3;
    }

    sigop_count += transaction_legacy_sigop_count(tx);

    // All other transactions must not be
    for(size_t i = 1; i < num_transactions; i++) {
        tx = block_transaction(block, i);

        if(transaction_is_coinbase(tx) == 1) {
            log_notice("block is invalid: transaction %d is a coinbase", (int)i);
            return -4;
        }

        if(check_transaction(tx) != 1) {
            log_notice("block is invalid: transaction %d isn't valid", (int)i);
            return -4;
        }

        sigop_count += transaction_legacy_sigop_count(tx);
    }

    // check legacy sigops count
    if(sigop_count > BLOCK_MAX_SIGOPS) {
        log_notice("block is invalid: too many legacy sigops");
        return -5;
    }

    // check the block's merkle root
    unsigned char calc_merkle_root[32];
    block_calculate_merkle_root(block, calc_merkle_root);

    unsigned char merkle_root[32];
    block_header_merkle_root(block_header(block), merkle_root);
    if(memcmp(merkle_root, calc_merkle_root, 32) != 0) {
        log_notice("block is invalid: bad merkle root");
        return -4;
    }

    return 0;
}

int chaind_handle_block(struct chaind* state, struct inv const* inv, struct block* block)
{
    int r;
    if((r = check_block(block)) < 0) return r;

    add_transactions_from_block_to_database(state->database, inv, block);

    // Insert the block into db as disconnected from the chain
    if(database_has_inv(state->database, inv) == 0) {
        database_add_disconnected_block(state->database, inv->hash, block);
    }

    // Try to extend the best chain as much as possible given this new block and the other orphans in the database.
    deque hashes_to_check;
    deque_init(&hashes_to_check);

    struct block_header* header = block_header(block);
    unsigned char previous_block_hash[32];
    block_header_previous_block_hash(header, previous_block_hash);

    unsigned char* hash = (unsigned char*)memdup(previous_block_hash, 32);
    deque_appendright(&hashes_to_check, (uintptr_t)hash);

    while(deque_count(&hashes_to_check) > 0) {
        hash = (unsigned char*)deque_popleft(&hashes_to_check);

#if 0
        {
            bytes_to_hexstring(hash, 32, s, 1);
            log_debug("checking %s", s);
        }
#endif

        // See if 'hash' block exists in the db, if it doesn't then we can't connect anything.
        struct blockchain_link* conn = database_get_blockchain_link(state->database, hash);
        if(conn == NULL) {
            free(hash);
            continue;
        }

        // If the connecting block isn't itself connected, we can't do anything...
        if(blockchain_link_connected(conn) == 0) {
            blockchain_link_free(conn);
            free(hash);
            continue;
        }

        // Find blocks that are referenced by the current block
        struct vector result;
        if(database_find_blockchain_links_by_previous_block_hash(state->database, hash, &result) < 0) {
            // error
            log_warning("error 1\n");
            break;
        }

        // vector is now a list of all blocks that has the previous_block_hash set to 'hash'
        // for each block found, we try connecting it and try expanding the best chain
        for(size_t i = 0; i < vector_count(&result); i++) {
            struct blockchain_link* link = (struct blockchain_link*)vector_get(&result, i);
            struct block_header* link_header = blockchain_link_block_header(link);
            unsigned char link_header_hash[32];
            block_header_hash(link_header, link_header_hash);

            // If the block to connect to is already connected, then we don't need to do any block-connection 
            // checks because they've already been done. We do need to follow non-main chains however, in 
            // case a newly connected chain -- that was connected by a block in the middle -- contains more work
            if(blockchain_link_connected(link) != 0) {
                if(blockchain_link_main(link) == 0) {
                    deque_appendright(&hashes_to_check, (uintptr_t)memdup(link_header_hash, 32));
                }

                blockchain_link_free(link);
                continue;
            }

#if 1
            {
                struct block_header* conn_header = blockchain_link_block_header(conn);
                unsigned char b[32], c[32];
                block_header_hash(conn_header, b);
                block_header_hash(link_header, c);
                bytes_to_hexstring(b, 32, s1, 1);
                bytes_to_hexstring(c, 32, s2, 1);
                log_debug("trying to connect %s to %s", s1, s2);
            }
#endif

            unsigned int height = blockchain_link_height(conn) + 1;
            unsigned int block_time = block_header_timestamp(link_header);

            int block_error = 0;
            
            // Verify the incoming block
            unsigned int start_retarget_height = blockchain_link_height(conn) - (blockchain_link_height(conn) % WORK_RETARGET_INTERVAL);

            // This is actually not quite correct: it should just iterate up the tree until it reaches a block at the proper interval
            // height.  The way this code works is to pick off the "main" chain, but it's not too bad because a chain fork of length 
            // WORK_RETARGET_INTERVAL is probably never, ever going to happen.
            struct blockchain_link* start_retarget = database_get_main_blockchain_link_at_height(state->database, start_retarget_height);
            assert(blockchain_link_main(start_retarget) == 1);

            // Verify the work on this block
            unsigned int next_bits = blockchain_link_get_next_bits(conn, start_retarget, block_time);
            assert(next_bits == block_header_bits(link_header));
            if(next_bits != block_header_bits(link_header)) {
                block_error |= 0x01;
            }

            // Verify the timestamp
            unsigned int median_time_past = blockchain_link_median_time_past(conn);
            if(block_header_timestamp(link_header) <= median_time_past) {
                block_error |= 0x02;
            }

            // Every transaction in the block must be final, so this is the point where we need the full block data
            struct block* block = database_get_block(state->database, link_header_hash);
            assert(block != NULL);

            size_t num_transactions = block_num_transactions(block);
            for(size_t i = 0; i < num_transactions; i++) {
                struct transaction* tx = block_transaction(block, i);

                if(transaction_is_final(tx, height, block_time) == 0) {
                    block_error |= 0x04;
                    break;
                }
            }

            // Version 2 blocks (after 750/1000 majority) require the coinbase to have the block height in it. If we pass the 
            // bigger majority for required version 2 blocks, then we don't need to compute the majority because it know it's true.
            if(block_header_version(link_header) >= 2) {
                if(height >= 227836 || is_block_version_majority(state->database, 2, 750, 1000, hash) == 1) {
                    // TODO check coinbase
                    block_error |= 0x08;
                }
            }

            // All blocks must be version 2 after 950/1000, which happened at block 227,836.
            // if(is_block_version_majority(state->database, 2, 950, 1000, hash) == 1 && block_header_version(link_header) < 2) {
            if(height >= 227836 && block_header_version(link_header) < 2) {
                block_error |= 0x10;
            }

            // Block needs to be verified for its transactions

            if(block_error == 0) {
                mpz_t work;
                mpz_init(work);
                blockchain_link_work(conn, work);

                mpz_t link_work;
                mpz_init(link_work);
                block_header_work(link_header, link_work);
                mpz_add(work, work, link_work);
                blockchain_link_set_work(link, work);

                // Not part of main chain, but connected
                blockchain_link_set_main(link, 0);
                blockchain_link_set_height(link, height);
                blockchain_link_set_connected(link, 1);

                database_connect_block(state->database, link_header_hash, link);
                database_set_median_time_past(state->database, link_header_hash, MEDIAN_TIME_PAST_INTERVAL);
                
                mpz_clear(work);
                mpz_clear(link_work);

                // TODO if this block would become the next best chain, then all transactions in this block
                // need to be check to make sure they only spend proper inputs
                set_best_blockchain_link(state, link_header_hash);

                deque_appendright(&hashes_to_check, (uintptr_t)memdup(link_header_hash, 32));
            } else {
                log_notice("block error %02X", block_error);
                assert(0);
            }

            block_free(block);
            blockchain_link_free(link);
        }

        vector_free(&result);

        // If this block connects (i.e., previous_block_hash exists), compute it's total work and update its height
        // and add this block hash to hashes_to_check

        // See if the chain referenced by 'hash' has more total work than the current state->blockchain, and if so
        // set it as the best chain, removing and adding blocks from 'main' as necessary

        blockchain_link_free(conn);
        free(hash);
    }

    deque_free(&hashes_to_check);

    return 0;
}

int chaind_handle_tx(struct chaind* state, struct inv const* inv, struct transaction* tx)
{
    // If it's not in the db, add this as an orphan tx
    if(database_has_inv(state->database, inv) == 0) {
        database_add_orphan_transaction(state->database, inv->hash, tx);
    }

    // TODO Add to some kind of recently-seen cache?

    return 0;
}
