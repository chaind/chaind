#ifndef __TRANSACTION_H
#define __TRANSACTION_H

#define TRANSACTION_HASH_SIZE 32

#define SIGHASH_ALL          1
#define SIGHASH_NONE         2
#define SIGHASH_SINGLE       3
#define SIGHASH_TYPEMASK     0x1F

#define SIGHASH_ANYONECANPAY 0x80

struct coin_view;
struct script;
struct transaction;
struct transaction_input;
struct transaction_output;
struct transaction_output_reference;

void transaction_output_reference_set_hash(struct transaction_output_reference*, unsigned char const*);
void transaction_output_reference_set_index(struct transaction_output_reference*, unsigned int);
void transaction_output_reference_hash(struct transaction_output_reference const*, unsigned char* out);
unsigned int transaction_output_reference_index(struct transaction_output_reference const*);
int transaction_output_reference_is_null(struct transaction_output_reference const*);

struct transaction_input* transaction_input_new();
void transaction_input_free(struct transaction_input*);
struct transaction_output_reference* transaction_input_output_reference(struct transaction_input*);
void transaction_input_set_script(struct transaction_input*, struct script*);
struct script* transaction_input_script(struct transaction_input*);
void transaction_input_set_sequence(struct transaction_input*, unsigned int);
unsigned int transaction_input_sequence(struct transaction_input const*);
int transaction_input_is_final(struct transaction_input const*);

struct transaction_output* transaction_output_new();
void transaction_output_free(struct transaction_output*);
void transaction_output_set_value(struct transaction_output*, uint64_t);
uint64_t transaction_output_value(struct transaction_output const*);
void transaction_output_set_script(struct transaction_output*, struct script*);
struct script* transaction_output_script(struct transaction_output*);

void transaction_set_version(struct transaction*, unsigned int);
unsigned int transaction_version(struct transaction const*);
void transaction_add_input(struct transaction*, struct transaction_input*);
void transaction_add_output(struct transaction*, struct transaction_output*);
size_t transaction_num_inputs(struct transaction const*);
size_t transaction_num_outputs(struct transaction const*);
struct transaction_input* transaction_input(struct transaction const*, size_t index);
struct transaction_output* transaction_output(struct transaction const*, size_t index);
void transaction_set_lock_time(struct transaction*, unsigned int);
unsigned int transaction_lock_time(struct transaction const*);
unsigned int transaction_legacy_sigop_count(struct transaction*);
unsigned int transaction_p2sh_sigop_count(struct transaction*, struct coin_view* cv);

struct transaction* transaction_genesis_coinbase();
struct transaction* transaction_new();
struct transaction* transaction_clone(struct transaction*);
void transaction_hash(struct transaction const*, unsigned char* out);
int transaction_hash_equals(struct transaction const*, unsigned char const*);
int transaction_hash_equals_string(struct transaction const*, char const*);
void transaction_free(struct transaction*);

int transaction_is_coinbase(struct transaction const*);
int transaction_is_final(struct transaction const*, size_t block_height, uint64_t block_time);
uint64_t transaction_total_output_value(struct transaction*);
int transaction_verify_input_signature(unsigned char* sig, size_t sig_size, unsigned char* pubkey, size_t pubkey_size, struct transaction* spending_transaction, size_t input_index, struct script* sig_script);

size_t serialize_transaction_output_reference(unsigned char* out, struct transaction_output_reference const*);
size_t serialize_transaction_input(unsigned char* out, struct transaction_input const*);
size_t serialize_transaction_output(unsigned char* out, struct transaction_output const*);
size_t serialize_transaction(unsigned char* out, struct transaction const*);
size_t serialize_transaction_for_signing(unsigned char* out, struct transaction const*, int input_index_to_sign, int sign_flags, struct script* input_script);

size_t unserialize_transaction_output_reference(unsigned char const* in, size_t in_size, struct transaction_output_reference* out);
size_t unserialize_transaction_input(unsigned char const* in, size_t in_size, struct transaction_input** out);
size_t unserialize_transaction_output(unsigned char const* in, size_t in_size, struct transaction_output** out);
size_t unserialize_transaction(unsigned char const* in, size_t in_size, struct transaction** out);

static inline size_t transaction_size(struct transaction const* tx) 
{
    return serialize_transaction(NULL, tx);
}

#endif /* __TRANSACTION_H */

