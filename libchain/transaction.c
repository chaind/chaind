#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>

#include "coin_view.h"
#include "crypto.h"
#include "hashes.h"
#include "script.h"
#include "serialize.h"
#include "transaction.h"
#include "util.h"

struct transaction_output_reference {
    unsigned char hash[32];
    unsigned int index;
};

struct transaction_input {
    struct transaction_output_reference output_reference;
    struct script* script;
    unsigned int sequence;
};

struct transaction_output {
    uint64_t value;
    struct script* script;
};

struct transaction {
    unsigned int version;
    void* inputs;
    void* outputs;
    unsigned int lock_time;
};

void transaction_output_reference_set_hash(struct transaction_output_reference* output_reference, unsigned char const* hash)
{
    memcpy(output_reference->hash, hash, sizeof(output_reference->hash));
}

void transaction_output_reference_set_index(struct transaction_output_reference* output_reference, unsigned int index)
{
    output_reference->index = index;
}

void transaction_output_reference_hash(struct transaction_output_reference const* output_reference, unsigned char* out)
{
    memcpy(out, output_reference->hash, sizeof(output_reference->hash));
}

unsigned int transaction_output_reference_index(struct transaction_output_reference const* output_reference)
{
    return output_reference->index;
}

int transaction_output_reference_is_null(struct transaction_output_reference const* output_reference)
{
    return ((memcmp(output_reference->hash, HASH_ZERO, 32) == 0) && (output_reference->index == 0xFFFFFFFF)) ? 1 : 0;
}

struct transaction_input* transaction_input_new()
{
    struct transaction_input* input = (struct transaction_input*)malloc(sizeof(struct transaction_input));
    zero(input);
    return input;
}

void transaction_input_free(struct transaction_input* input)
{
    if(input->script != NULL) script_free(input->script);
    free(input);
}

struct transaction_output_reference* transaction_input_output_reference(struct transaction_input* input)
{
    return &input->output_reference;
}

void transaction_input_set_script(struct transaction_input* input, struct script* script)
{
    if(input->script != NULL) script_free(input->script);
    input->script = script;
}

struct script* transaction_input_script(struct transaction_input* input)
{
    return input->script;
}

void transaction_input_set_sequence(struct transaction_input* input, unsigned int sequence)
{
    input->sequence = sequence;
}

unsigned int transaction_input_sequence(struct transaction_input const* input)
{
    return input->sequence;
}

int transaction_input_is_final(struct transaction_input const* input)
{
    return (transaction_input_sequence(input) == 0xFFFFFFFF) ? 1 : 0;
}

struct transaction_output* transaction_output_new()
{
    struct transaction_output* output = (struct transaction_output*)malloc(sizeof(struct transaction_output));
    zero(output);
    return output;
}

void transaction_output_free(struct transaction_output* output)
{
    if(output->script != NULL) script_free(output->script);
    free(output);
}

void transaction_output_set_value(struct transaction_output* output, uint64_t value)
{
    output->value = value;
}

uint64_t transaction_output_value(struct transaction_output const* output)
{
    return output->value;
}

void transaction_output_set_script(struct transaction_output* output, struct script* script)
{
    output->script = script;
}

struct script* transaction_output_script(struct transaction_output* output)
{
    return output->script;
}

void transaction_set_version(struct transaction* tx, unsigned int version)
{
    tx->version = version;
}

unsigned int transaction_version(struct transaction const* tx)
{
    return tx->version;
}

void transaction_add_input(struct transaction* tx, struct transaction_input* input)
{
    Word_t i = (Word_t)transaction_num_inputs(tx);
    struct transaction_input** pinput;
    JLI(pinput, tx->inputs, i);
    *pinput = input;
}

void transaction_add_output(struct transaction* tx, struct transaction_output* output)
{
    Word_t i = (Word_t)transaction_num_outputs(tx);
    struct transaction_output** poutput;
    JLI(poutput, tx->outputs, i);
    *poutput = output;
}

size_t transaction_num_inputs(struct transaction const* tx)
{
    Word_t rc;
    JLC(rc, tx->inputs, 0, -1);
    return (size_t)rc;
}

size_t transaction_num_outputs(struct transaction const* tx)
{
    Word_t rc;
    JLC(rc, tx->outputs, 0, -1);
    return (size_t)rc;
}

struct transaction_input* transaction_input(struct transaction const* tx, size_t index)
{
    struct transaction_input** pinput;
    Word_t i = (Word_t)index;
    JLG(pinput, tx->inputs, i);
    if(pinput == NULL) return NULL;
    return *pinput;
}

struct transaction_output* transaction_output(struct transaction const* tx, size_t index)
{
    struct transaction_output** poutput;
    Word_t i = (Word_t)index;
    JLG(poutput, tx->outputs, i);
    if(poutput == NULL) return NULL;
    return *poutput;
}

void transaction_set_lock_time(struct transaction* tx, unsigned int lock_time)
{
    tx->lock_time = lock_time;
}

unsigned int transaction_lock_time(struct transaction const* tx)
{
    return tx->lock_time;
}

unsigned int transaction_legacy_sigop_count(struct transaction* tx)
{
    unsigned int r = 0;

    size_t num_inputs = transaction_num_inputs(tx);
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        struct script* script = transaction_input_script(input);
        r += script_legacy_sigop_count(script, 0);
    }

    size_t num_outputs = transaction_num_outputs(tx);
    for(size_t i = 0; i < num_outputs; i++) {
        struct transaction_output* output = transaction_output(tx, i);
        struct script* script = transaction_output_script(output);
        r += script_legacy_sigop_count(script, 0);
    }

    return r;
}

unsigned int transaction_p2sh_sigop_count(struct transaction* tx, struct coin_view* cv)
{
    if(transaction_is_coinbase(tx)) return 0;
    unsigned int r = 0;

    size_t num_inputs = transaction_num_inputs(tx);
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        struct transaction_output_reference* output_reference = transaction_input_output_reference(input);
        unsigned char hash[32];
        transaction_output_reference_hash(output_reference, hash);

        struct transaction* tx = NULL;
        int result = coin_view_find_blockchain_transaction(cv, hash, &tx, NULL);
        assert(result == 1);
        assert(transaction_output_reference_index(output_reference) < transaction_num_outputs(tx));

        struct script* script = transaction_output_script(transaction_output(tx, transaction_output_reference_index(output_reference)));
        assert(script != NULL);

        if(script_is_p2sh(script)) {
            r += script_p2sh_sigop_count(script, transaction_input_script(input));
        }

        transaction_free(tx);
    }

    return r;
}

struct transaction* transaction_genesis_coinbase()
{
    static struct transaction genesis_coinbase = {
        1,
        NULL,
        NULL,
        0
    };

    if(genesis_coinbase.inputs == NULL) {
        static unsigned char genesis_coinbase_input_script_bytes[0x4d] = {
            0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45, 0x54, 0x68, 0x65, 0x20, 0x54, 0x69, 0x6d,
            0x65, 0x73, 0x20, 0x30, 0x33, 0x2f, 0x4a, 0x61, 0x6e, 0x2f, 0x32, 0x30, 0x30, 0x39, 0x20,
            0x43, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x6f, 0x72, 0x20, 0x6f, 0x6e, 0x20, 0x62,
            0x72, 0x69, 0x6e, 0x6b, 0x20, 0x6f, 0x66, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20,
            0x62, 0x61, 0x69, 0x6c, 0x6f, 0x75, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x62, 0x61, 0x6e,
            0x6b, 0x73
        };

        struct transaction_input* genesis_coinbase_input = (struct transaction_input*)malloc(sizeof(struct transaction_input));
        memset(genesis_coinbase_input->output_reference.hash, 0, sizeof(genesis_coinbase_input->output_reference.hash));
        genesis_coinbase_input->output_reference.index = 0xFFFFFFFF;

        unserialize_script(genesis_coinbase_input_script_bytes, 
                           sizeof(genesis_coinbase_input_script_bytes), 
                           &genesis_coinbase_input->script, 
                           sizeof(genesis_coinbase_input_script_bytes));

        genesis_coinbase_input->sequence = 0xFFFFFFFF;

        struct transaction_input** pinput;
        Word_t index = 0;
        JLI(pinput, genesis_coinbase.inputs, index);
        assert(pinput != NULL);
        *pinput = genesis_coinbase_input;
    }

    if(genesis_coinbase.outputs == NULL) {
        static unsigned char genesis_coinbase_output_script_bytes[0x43] = {
            0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 
            0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 
            0x1f, 0x61, 0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 
            0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 
            0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f, 0xac
        };

        struct transaction_output* genesis_coinbase_output = (struct transaction_output*)malloc(sizeof(struct transaction_output));

        genesis_coinbase_output->value = 5000000000ULL;
        unserialize_script(genesis_coinbase_output_script_bytes, 
                           sizeof(genesis_coinbase_output_script_bytes), 
                           &genesis_coinbase_output->script, 
                           sizeof(genesis_coinbase_output_script_bytes));

        struct transaction_output** poutput;
        Word_t index = 0;
        JLI(poutput, genesis_coinbase.outputs, index);
        assert(poutput != NULL);
        *poutput = genesis_coinbase_output;
    }

    return &genesis_coinbase;
}

void transaction_hash(struct transaction const* tx, unsigned char* out)
{
    size_t tx_size = transaction_size(tx);
    unsigned char* buf = (unsigned char*)alloca(tx_size);
    size_t r = serialize_transaction(buf, tx);
    assert(tx_size == r);
    sha256_sha256(buf, tx_size, out);
}

int transaction_hash_equals(struct transaction const* tx, unsigned char const* m)
{
    unsigned char hash[32];
    transaction_hash(tx, hash);
    return (memcmp(hash, m, 32) == 0) ? 1 : 0;
}

int transaction_hash_equals_string(struct transaction const* tx, char const* s)
{
    hexstring_to_bytes(s, 32, h, 1);
    return transaction_hash_equals(tx, h);
}

struct transaction* transaction_new()
{
    struct transaction* tx = (struct transaction*)malloc(sizeof(struct transaction));
    zero(tx);
    return tx;
}

struct transaction* transaction_clone(struct transaction* tx)
{
    struct transaction* clone = transaction_new();
    transaction_set_version(clone, transaction_version(tx));

    size_t num_inputs = transaction_num_inputs(tx);
    for(size_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = transaction_input(tx, i);
        struct transaction_input* input_clone = transaction_input_new();
        memcpy(transaction_input_output_reference(input_clone),
               transaction_input_output_reference(input),
               sizeof(struct transaction_output_reference));
        transaction_input_set_script(input_clone, script_clone(transaction_input_script(input)));
        transaction_input_set_sequence(input_clone, transaction_input_sequence(input));
        transaction_add_input(clone, input_clone);
    }

    size_t num_outputs = transaction_num_outputs(tx);
    for(size_t i = 0; i < num_outputs; i++) {
        struct transaction_output* output = transaction_output(tx, i);
        struct transaction_output* output_clone = transaction_output_new();
        transaction_output_set_value(output_clone, transaction_output_value(output));
        transaction_output_set_script(output_clone, script_clone(transaction_output_script(output)));
        transaction_add_output(clone, output_clone);
    }

    transaction_set_lock_time(clone, transaction_lock_time(tx));
    return clone;
}

void transaction_free(struct transaction* tx)
{
    int rc;
    Word_t index = 0;

    struct transaction_output** poutput = NULL;
    JLF(poutput, tx->outputs, index);
    while(poutput != NULL) {
        struct transaction_output* output = *poutput;
        transaction_output_free(output);
        JLN(poutput, tx->outputs, index);
    }

    JLFA(rc, tx->outputs);

    index = 0;
    struct transaction_input** pinput = NULL;
    JLF(pinput, tx->inputs, index);
    while(pinput != NULL) {
        struct transaction_input* input = *pinput;
        transaction_input_free(input);
        JLN(pinput, tx->inputs, index);
    }

    JLFA(rc, tx->inputs);

    free(tx);
}

int transaction_is_coinbase(struct transaction const* tx)
{
    if(transaction_num_inputs(tx) == 1) {
        return transaction_output_reference_is_null(transaction_input_output_reference(transaction_input(tx, 0)));
    }

    return 0;
}

int transaction_is_final(struct transaction const* tx, size_t block_height, uint64_t block_time)
{
    if(transaction_lock_time(tx) == 0) return 1;

    if(transaction_lock_time(tx) < (transaction_lock_time(tx) < 500000000 ? block_height : block_time)) return 1;

    size_t num_inputs = transaction_num_inputs(tx);
    for(size_t i = 0; i < num_inputs; i++) {
        if(transaction_input_is_final(transaction_input(tx, i)) == 0) return 0;
    }

    return 1;
}

uint64_t transaction_total_output_value(struct transaction* tx)
{
    uint64_t total = 0;
    size_t num_outputs = transaction_num_outputs(tx);

    for(size_t i = 0; i < num_outputs; i++) {
        total += transaction_output_value(transaction_output(tx, i));
    }

    return total;
}

int transaction_verify_input_signature(unsigned char* sig, size_t sig_size, unsigned char* pubkey, size_t pubkey_size, struct transaction* spending_transaction, size_t input_index, struct script* sig_script)
{
    if(input_index >= transaction_num_inputs(spending_transaction)) return 0;

    if(crypto_is_valid_public_key(pubkey, pubkey_size) != 1) return 0;

    if(sig_size < 1) return 0;
    unsigned char sign_flags = sig[sig_size - 1];
    sig_size -= 1;

    if((sign_flags & SIGHASH_TYPEMASK) == SIGHASH_SINGLE) {
        if(input_index >= transaction_num_outputs(spending_transaction)) return 0;
    }

    size_t serialize_size = serialize_transaction_for_signing(NULL, spending_transaction, input_index, sign_flags, sig_script);
    unsigned char* buffer = (unsigned char*)alloca(sizeof(unsigned char) * (serialize_size + 4));
    size_t offset = serialize_transaction_for_signing(buffer, spending_transaction, input_index, sign_flags, sig_script);
    offset += serialize_uint32(&buffer[offset], sign_flags);

    unsigned char hash[32];
    sha256_sha256(buffer, serialize_size + 4, hash);

    return crypto_verify_signature(sig, sig_size, pubkey, pubkey_size, hash);
}

size_t serialize_transaction_output_reference(unsigned char* out, struct transaction_output_reference const* in)
{
    size_t offset = 0;

    offset += serialize_bytes(out == NULL ? NULL : &out[offset], &in->hash[0], 32);
    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->index);

    return offset;
}

size_t serialize_transaction_input(unsigned char* out, struct transaction_input const* in)
{
    size_t offset = 0;

    offset += serialize_transaction_output_reference(out == NULL ? NULL : &out[offset], &in->output_reference);

    size_t script_length = script_size(in->script);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)script_length);
    offset += serialize_script(out == NULL ? NULL : &out[offset], in->script, script_length);

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->sequence);
    return offset;
}

size_t serialize_transaction_input_for_signing(unsigned char* out, struct transaction_input const* in, int use_script, int sign_flags, struct script* sig_script)
{
    size_t offset = 0;

    offset += serialize_transaction_output_reference(out == NULL ? NULL : &out[offset], &in->output_reference);
    
    if(use_script != 1) {
        struct script* script = script_static_empty();
        size_t script_length = script_size(script);
        offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)script_length);
        offset += serialize_script(out == NULL ? NULL : &out[offset], script, script_length);

    } else {
        size_t script_length = serialize_script_for_signing(NULL, sig_script);
        offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)script_length);
        offset += serialize_script_for_signing(out == NULL ? NULL : &out[offset], sig_script);
    }

    int sign_method = sign_flags & SIGHASH_TYPEMASK;
    if((use_script != 1) && (sign_method == SIGHASH_SINGLE || sign_method == SIGHASH_NONE)) {
        offset += serialize_uint32(out == NULL ? NULL : &out[offset], 0);
    } else {
        offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->sequence);
    }

    return offset;
}

size_t serialize_transaction_output(unsigned char* out, struct transaction_output const* in)
{
    size_t offset = 0;

    offset += serialize_uint64(out == NULL ? NULL : &out[offset], in->value);

    size_t script_length = script_size(in->script);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], script_length);
    offset += serialize_script(out == NULL ? NULL : &out[offset], in->script, script_length);

    return offset;
}

size_t serialize_transaction(unsigned char* out, struct transaction const* in)
{
    size_t offset = 0;

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->version);

    // serialize inputs
    size_t num_inputs = transaction_num_inputs(in);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)num_inputs);

    for(Word_t i = 0; i < (Word_t)num_inputs; i++) {
        struct transaction_input* input = transaction_input(in, i);
        assert(input != NULL);
        offset += serialize_transaction_input(out == NULL ? NULL : &out[offset], input);
    }

    // serialize outputs
    size_t num_outputs = transaction_num_outputs(in);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)num_outputs);

    for(Word_t i = 0; i < (Word_t)num_outputs; i++) {
        struct transaction_output* output = transaction_output(in, i);
        assert(output != NULL);
        offset += serialize_transaction_output(out == NULL ? NULL : &out[offset], output);
    }

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->lock_time);
    return offset;
}

size_t serialize_transaction_for_signing(unsigned char* out, struct transaction const* in, int input_index_to_sign, int sign_flags, struct script* input_script)
{
    size_t offset = 0;

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->version);

    int is_anyonecanpay = ((sign_flags & SIGHASH_ANYONECANPAY) == SIGHASH_ANYONECANPAY);
    size_t num_inputs = is_anyonecanpay ? 1 : transaction_num_inputs(in);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)num_inputs);

    for(size_t i = 0; i < num_inputs; i++) {
        size_t index = (is_anyonecanpay) ? input_index_to_sign : i;
        struct transaction_input* input = transaction_input(in, index);
        assert(input != NULL);
        offset += serialize_transaction_input_for_signing(out == NULL ? NULL : &out[offset], input, index == input_index_to_sign, sign_flags, input_script);
    }

    int is_single = (sign_flags & SIGHASH_TYPEMASK) == SIGHASH_SINGLE;
    size_t num_outputs = ((sign_flags & SIGHASH_TYPEMASK) == SIGHASH_NONE) ? 0 : (is_single ? (input_index_to_sign + 1) : transaction_num_outputs(in));
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)num_outputs);

    for(size_t i = 0; i < num_outputs; i++) {
        if(is_single) {
            struct transaction_output output;
            output.value = 0;
            output.script = script_static_empty();
            offset += serialize_transaction_output(out == NULL ? NULL : &out[offset], &output);
        } else {
            struct transaction_output* output = transaction_output(in, i);
            assert(output != NULL);
            offset += serialize_transaction_output(out == NULL ? NULL : &out[offset], output);
        }
    }

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->lock_time);
    return offset;
}

size_t unserialize_transaction_output_reference(unsigned char const* in, size_t in_size, struct transaction_output_reference* out)
{
    size_t r, offset = 0;

    offset += (r = unserialize_bytes(&in[offset], in_size - offset, &out->hash[0], 32));
    if(r != 32) return 0;

    offset += (r = unserialize_uint32(&in[offset], in_size - offset, &out->index));
    if(r == 0) return 0;

    return offset;
}

size_t unserialize_transaction_input(unsigned char const* in, size_t in_size, struct transaction_input** out)
{
    size_t r, offset = 0;
    struct transaction_input* input = (struct transaction_input*)malloc(sizeof(struct transaction_input));
    zero(input);

    offset += (r = unserialize_transaction_output_reference(&in[offset], in_size - offset, &input->output_reference));
    if(r == 0) goto bad;

    uint64_t script_length;
    offset += (r = unserialize_variable_uint(&in[offset], in_size - offset, &script_length));
    if(r == 0) goto bad;

    offset += (r = unserialize_script(&in[offset], in_size - offset, &input->script, (size_t)script_length));
    if(r == 0) goto bad;

    offset += (r = unserialize_uint32(&in[offset], in_size - offset, &input->sequence));
    if(r == 0) goto bad;

    *out = input;
    return offset;
bad:
    if(input->script != NULL) script_free(input->script);
    if(input != NULL) free(input);
    return 0;
}

size_t unserialize_transaction_output(unsigned char const* in, size_t in_size, struct transaction_output** out)
{
    size_t r, offset = 0;
    struct transaction_output* output = (struct transaction_output*)malloc(sizeof(struct transaction_output));

    offset += (r = unserialize_uint64(&in[offset], in_size - offset, &output->value));
    if(r == 0) goto bad;

    uint64_t script_length;
    offset += (r = unserialize_variable_uint(&in[offset], in_size - offset, &script_length));
    if(r == 0) goto bad;

    offset += (r = unserialize_script(&in[offset], in_size - offset, &output->script, (size_t)script_length));
    if(r == 0) goto bad;

    *out = output;
    return offset;
bad:
    if(output->script != NULL) script_free(output->script);
    if(output != NULL) free(output);
    return 0;
}

size_t unserialize_transaction(unsigned char const* in, size_t in_size, struct transaction** out)
{
    size_t r, offset = 0;
    struct transaction* tx = (struct transaction*)malloc(sizeof(struct transaction));
    zero(tx);

    if(in_size < 4) goto bad;
    offset += unserialize_uint32(&in[offset], in_size - offset, &tx->version);

    uint64_t num_inputs;
    offset += (r = unserialize_variable_uint(&in[offset], in_size - offset, &num_inputs));
    if(r == 0) goto bad;

    for(uint64_t i = 0; i < num_inputs; i++) {
        struct transaction_input* input = NULL, **pinput = NULL;
        offset += (r = unserialize_transaction_input(&in[offset], in_size - offset, &input));
        if(r == 0) goto bad;

        Word_t index = (Word_t)i;
        JLI(pinput, tx->inputs, index);
        assert(pinput != NULL);
        *pinput = input;
    }

    uint64_t num_outputs;
    offset += (r = unserialize_variable_uint(&in[offset], in_size - offset, &num_outputs));
    if(r == 0) goto bad;

    for(uint64_t i = 0; i < num_outputs; i++) {
        struct transaction_output* output = NULL, **poutput = NULL;
        offset += (r = unserialize_transaction_output(&in[offset], in_size - offset, &output));
        if(r == 0) goto bad;

        Word_t index = (Word_t)i;
        JLI(poutput, tx->outputs, index);
        assert(poutput != NULL);
        *poutput = output;
    }

    offset += (r = unserialize_uint32(&in[offset], in_size - offset, &tx->lock_time));
    if(r == 0) goto bad;

    *out = tx;
    return offset;
bad:
    if(tx != NULL) transaction_free(tx);
    return 0;
}

