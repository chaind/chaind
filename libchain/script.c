#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gmp.h>

#include "hashes.h"
#include "script.h"
#include "serialize.h"
#include "transaction.h"
#include "util.h"
#include "vector.h"

static size_t const MAX_SCRIPT_ELEMENT_SIZE = 520; // in bytes
static size_t const MAX_SCRIPT_OPCODE_COUNT = 201; 
static size_t const MAX_STACK_HEIGHT = 1000;

struct script {
    unsigned char* data;
    size_t size;
};

struct script_stack_element {
    unsigned char* data;
    size_t size;
};

struct script_stack {
    struct vector stack;
};

static int script_execute(struct script*, struct script_stack*, struct transaction*, size_t); 
static int script_delete_piece(struct script*, unsigned char*, size_t);

static struct script_stack* script_stack_new();
static void script_stack_free(struct script_stack*);
static struct script_stack* script_stack_clone(struct script_stack*);
static void script_stack_pop(struct script_stack*);

static struct script_stack_element* make_stack_element(unsigned char*, size_t);
static void free_stack_element(struct script_stack_element*);
static void make_push_data(struct script_stack_element*, unsigned char* out, size_t* );

struct script* script_static_empty()
{
    static struct script empty = {
        (unsigned char*)"",
        0
    };

    return &empty;
}

struct script* script_clone(struct script* script)
{
    struct script* clone = (struct script*)malloc(sizeof(struct script));
    clone->data = (unsigned char*)memdup(script->data, script->size);
    clone->size = script->size;
    return clone;
}

void script_free(struct script* script)
{
    if(script->data != NULL) free(script->data);
    free(script);
}

unsigned char* script_data(struct script* script)
{
    return script->data;
}

size_t script_size(struct script const* script)
{
    return script->size;
}

static int next_opcode(struct script const* script, size_t pc, enum script_opcode* opcode, size_t* opcode_size, unsigned char** push_data, size_t* push_data_size)
{
    size_t old_pc = pc;

    if(pc >= script->size) {
        return 0;
    }

    if(push_data_size != NULL) *push_data_size = 0;

    enum script_opcode result = (enum script_opcode)script->data[pc];
    pc += 1;

    if(SCRIPT_OPCODE_0 < result && result <= SCRIPT_OPCODE_PUSHDATA4) {
        size_t size = 0;
        if(result < SCRIPT_OPCODE_PUSHDATA1) {
            size = (size_t)result;
        } else if(result == SCRIPT_OPCODE_PUSHDATA1) {
            if(pc >= script->size) return 0;
            size = (size_t)script->data[pc];
            pc += 1;
        } else if(result == SCRIPT_OPCODE_PUSHDATA2) {
            if((pc + 2) >= script->size) return 0;
            size = (size_t)((unsigned int)script->data[pc] | ((unsigned int)script->data[pc + 1] << 8));
            pc += 2;
        } else if(result == SCRIPT_OPCODE_PUSHDATA4) {
            if((pc + 4) >= script->size) return 0;
            size = (size_t)((unsigned int)script->data[pc] | ((unsigned int)script->data[pc + 1] << 8) 
                              | ((unsigned int)script->data[pc + 2] << 16) | ((unsigned int)script->data[pc + 3] << 24));
            pc += 4;
        }

        if(size == 0 || ((size_t)pc + size) > script->size) return 0;
        if(push_data != NULL) *push_data = &script->data[pc];
        if(push_data_size != NULL) *push_data_size = size;
        pc += size;
    }

    *opcode = result;
    *opcode_size = (pc - old_pc);
    return 1;
}

int script_is_p2sh(struct script const* script)
{
    return (script->size == 23 
         && script->data[0] == (unsigned char)SCRIPT_OPCODE_HASH160
         && script->data[1] == 0x14
         && script->data[22] == (unsigned char)SCRIPT_OPCODE_EQUAL) ? 1 : 0;
}

int script_is_push_only(struct script const* script)
{
    size_t pc = 0;

    while(pc < script->size) {
        enum script_opcode opcode = SCRIPT_OPCODE_INVALID;
        size_t opcode_size = 0;
        
        if(next_opcode(script, pc, &opcode, &opcode_size, NULL, NULL) == 0) return 0;

        if(opcode == SCRIPT_OPCODE_INVALID) return 0;

        if((int)opcode > (int)SCRIPT_OPCODE_16) return 0;

        pc += opcode_size;
    }

    return 1;
}

unsigned int script_legacy_sigop_count(struct script const* script, int accurate)
{
    unsigned int r = 0;
    size_t pc = 0;

    enum script_opcode last_opcode = SCRIPT_OPCODE_INVALID;

    while(pc < script->size) {
        enum script_opcode opcode = SCRIPT_OPCODE_INVALID;
        size_t opcode_size = 0;
        
        if(next_opcode(script, pc, &opcode, &opcode_size, NULL, NULL) == 0) break;

        if(opcode == SCRIPT_OPCODE_INVALID) break;
        pc += opcode_size;

        if(opcode == SCRIPT_OPCODE_CHECKSIG || opcode == SCRIPT_OPCODE_CHECKSIGVERIFY) {
            r += 1;
        } else if(opcode == SCRIPT_OPCODE_CHECKMULTISIG || opcode == SCRIPT_OPCODE_CHECKMULTISIGVERIFY) {
            if((accurate != 0) && last_opcode >= SCRIPT_OPCODE_1 && last_opcode <= SCRIPT_OPCODE_16) {
                r += SCRIPT_OPCODE_DECODE_N(last_opcode);
            } else {
                r += 20;
            }
        }

        last_opcode = opcode;
    }

    return r;
}

unsigned int script_p2sh_sigop_count(struct script const* output_script, struct script const* spend_script)
{
    if(script_is_p2sh(output_script) != 1) return script_legacy_sigop_count(output_script, 1);

    // Extract the redemption script and count the # of sigops in that
    size_t pc = 0;
    unsigned char* last_push = NULL;
    size_t last_push_size = 0;
    while(pc < spend_script->size) {
        enum script_opcode opcode = SCRIPT_OPCODE_INVALID;
        size_t opcode_size;

        if(next_opcode(spend_script, pc, &opcode, &opcode_size, &last_push, &last_push_size) == 0) {
            return 0;
        }

        if((int)opcode > (int)SCRIPT_OPCODE_16) {
            return 0;
        }

        pc += opcode_size;
    }

    assert(last_push != NULL);

    // create a subscript
    struct script subscript;
    subscript.size = last_push_size;
    subscript.data = last_push;
    return script_legacy_sigop_count(&subscript, 1);
}

static struct script_stack* script_stack_new()
{
    struct script_stack* stack = (struct script_stack*)malloc(sizeof(struct script_stack));
    zero(stack);
    vector_init(&stack->stack);
    return stack;
}

static void script_stack_free(struct script_stack* stack)
{
    size_t n = vector_count(&stack->stack);
    for(size_t i = 0; i < n; i++) {
        script_stack_pop(stack);
    }
    vector_free(&stack->stack);
    free(stack);
}

static struct script_stack* script_stack_clone(struct script_stack* stack)
{
    struct script_stack* clone = script_stack_new();

    size_t height = vector_count(&stack->stack);
    for(size_t i = 0; i < height; i++) {
        struct script_stack_element* element = (struct script_stack_element*)vector_get(&stack->stack, i);
        vector_add(&clone->stack, (uintptr_t)make_stack_element(element->data, element->size));
    }

    return clone;
}

static void script_stack_pop(struct script_stack* stack)
{
    struct script_stack_element* element = (struct script_stack_element*)vector_pop(&stack->stack);
    free_stack_element(element);
}

static struct script_stack_element* make_stack_element(unsigned char* data, size_t size)
{
    struct script_stack_element* element = (struct script_stack_element*)malloc(sizeof(struct script_stack_element));
    element->data = memdup(data, size);
    element->size = size;
    return element;
}

static void free_stack_element(struct script_stack_element* element)
{
    free(element->data);
    free(element);
}

static void make_push_data(struct script_stack_element* element, unsigned char* out, size_t* size)
{
    if(element->size < (int)SCRIPT_OPCODE_PUSHDATA1) {
        out[0] = (unsigned char)element->size;
        memcpy(&out[1], element->data, element->size);
        *size = element->size + 1;
    } else if(element->size < 0x100) {
        out[0] = (unsigned char)SCRIPT_OPCODE_PUSHDATA1;
        out[1] = (unsigned char)element->size;
        memcpy(&out[2], element->data, element->size);
        *size = element->size + 2;
    } else if(element->size < 0x10000) {
        out[0] = (unsigned char)SCRIPT_OPCODE_PUSHDATA2;
        out[1] = (unsigned char)(element->size & 0xFF);
        out[2] = (unsigned char)((element->size & 0xFF00) >> 8);
        memcpy(&out[3], element->data, element->size);
        *size = element->size + 3;
    } else if(element->size < 0x100000000ULL) {
        out[0] = (unsigned char)SCRIPT_OPCODE_PUSHDATA4;
        out[1] = (unsigned char)(element->size & 0x000000FF);
        out[2] = (unsigned char)((element->size & 0x0000FF00) >> 8);
        out[3] = (unsigned char)((element->size & 0x00FF0000) >> 16);
        out[4] = (unsigned char)((element->size & 0xFF000000) >> 24);
        memcpy(&out[5], element->data, element->size);
        *size = element->size + 5;
    } else {
        assert(0);
    }
}

static struct script_stack_element* make_bool(int r)
{
    return make_stack_element(r != 0 ? (unsigned char*)"\x01" : (unsigned char*)"\x00", 1);
}

static struct script_stack_element* make_uint8(unsigned char v)
{
    return make_stack_element(&v, 1);
}

static struct script_stack_element* make_num(mpz_t n)
{
    // base 2 = number of bits, round up to bytes
    size_t count = (mpz_sizeinbase(n, 2) + 7) / 8;
    unsigned char* out = (unsigned char*)alloca(sizeof(unsigned char) * count);

    mpz_export(out,   // out buffer
               count, // out buffer size
               -1,    // endian (-1 = LSB)
               1,     // bytes per "word"
               1,     // per-word bit order
               0,     // skip bits
               n);    // src

    return make_stack_element(out, count);
}

static int get_bool(struct script_stack_element* element)
{
    for(size_t i = 0; i < element->size; i++) {
        if(element->data[i] != 0) {
            if(i == (element->size - 1) && element->data[i] == 0x80) {
                return 0;
            }
            return 1;
        }
    }
    return 0;
}

static void get_num(struct script_stack_element* element, mpz_t out)
{
    // Import element as a little-endian number
    if(element->size > 0) {
        mpz_import(out, element->size, -1, sizeof(element->data[0]), 1, 0, element->data);
    } else {
        mpz_set_ui(out, 0);
    }
}

static unsigned int get_uint32(struct script_stack_element* element)
{
    mpz_t r;
    mpz_init(r);
    get_num(element, r);
    unsigned int v = mpz_get_ui(r);
    mpz_clear(r);
    return v;
}

int script_verify(struct script* coins, struct transaction* spending_transaction, size_t input_index)
{
    int result = 0;

    assert(input_index < transaction_num_inputs(spending_transaction));

    struct script* spend = transaction_input_script(transaction_input(spending_transaction, input_index));
    assert(spend != NULL);

    struct script_stack* stack = script_stack_new();
    struct script_stack* stack_clone = NULL;
    struct script* p2sh = NULL;

    if((result = script_execute(spend, stack, spending_transaction, input_index)) <= 0) {
        assert(0);
        goto done;
    }

    stack_clone = script_stack_clone(stack);

    if((result = script_execute(coins, stack, spending_transaction, input_index)) <= 0) {
        assert(0);
        goto done;
    }

    if(vector_count(&stack->stack) == 0) {
        assert(0);
        result = -10;
        goto done;
    }

    struct script_stack_element* top = (struct script_stack_element*)vector_get(&stack->stack, vector_count(&stack->stack) - 1);
    result = get_bool(top);
    if(result == 0) {
        assert(0);
        goto done;
    }

    if(script_is_p2sh(coins)) {
        if(script_is_push_only(spend) != 1) {
            assert(0);
            result = -11;
            goto done;
        }

        assert(vector_count(&stack_clone->stack) > 0);
        top = (struct script_stack_element*)vector_get(&stack_clone->stack, vector_count(&stack_clone->stack) - 1);

        if(unserialize_script(top->data, top->size, &p2sh, top->size) != top->size) {
            assert(0);
            result = -12;
            goto done;
        }

        script_stack_pop(stack_clone);

        if((result = script_execute(p2sh, stack_clone, spending_transaction, input_index)) <= 0) {
            result = -13;
            goto done;
        }

        if(vector_count(&stack_clone->stack) == 0) {
            assert(0);
            result = -14;
            goto done;
        }

        top = (struct script_stack_element*)vector_get(&stack_clone->stack, vector_count(&stack_clone->stack) - 1);
        result = get_bool(top);
        printf("P2sh result = %d\n", result);
    }

done:
    if(p2sh != NULL) script_free(p2sh);
    script_stack_free(stack);
    if(stack_clone != NULL) script_stack_free(stack_clone);
    return result;
}

static int script_execute(struct script* script, struct script_stack* stack, struct transaction* spending_transaction, size_t input_index)
{
    if(script->size > 10000) return -1;

    size_t opcode_count = 0;

    // code separator support
    unsigned char* code_separator = &script->data[0];
    size_t code_separator_size = script->size;

    size_t pc = 0;
    while(pc < script->size) {
        enum script_opcode opcode = SCRIPT_OPCODE_INVALID;
        size_t opcode_size = 0;
        
        unsigned char* push_data;
        size_t push_data_size;

        if(next_opcode(script, pc, &opcode, &opcode_size, &push_data, &push_data_size) == 0) {
            // Couldn't get the next opcode despite not being at the end of the script
            return -2;
        }

        pc += opcode_size;
        
        if(push_data_size > MAX_SCRIPT_ELEMENT_SIZE) {
            // Script push too large
            return -3;
        }

        // Count # of opcodes, if we have too many bail
        if((int)opcode > (int)SCRIPT_OPCODE_16) {
            opcode_count += 1;
            if(opcode_count > MAX_SCRIPT_OPCODE_COUNT) {
                // Too long of a script
                return -4;
            }
        }

        // There are a list of disabled opcodes in Bitcoin Core
        if (opcode == SCRIPT_OPCODE_CAT || opcode == SCRIPT_OPCODE_SUBSTR || opcode == SCRIPT_OPCODE_LEFT || opcode == SCRIPT_OPCODE_RIGHT
          || opcode == SCRIPT_OPCODE_INVERT || opcode == SCRIPT_OPCODE_AND || opcode == SCRIPT_OPCODE_OR || opcode == SCRIPT_OPCODE_XOR 
          || opcode == SCRIPT_OPCODE_2MUL || opcode == SCRIPT_OPCODE_2DIV || opcode == SCRIPT_OPCODE_MUL || opcode == SCRIPT_OPCODE_DIV 
          || opcode == SCRIPT_OPCODE_MOD || opcode == SCRIPT_OPCODE_LSHIFT || opcode == SCRIPT_OPCODE_RSHIFT) {
            return -5;
        }

        if((int)opcode <= (int)SCRIPT_OPCODE_PUSHDATA4) {
            vector_add(&stack->stack, (uintptr_t)make_stack_element(push_data, push_data_size));
        } else {
            size_t stack_size = vector_count(&stack->stack);

            switch(opcode) {
            case SCRIPT_OPCODE_1NEGATE:
            case SCRIPT_OPCODE_1:
            case SCRIPT_OPCODE_2:
            case SCRIPT_OPCODE_3:
            case SCRIPT_OPCODE_4:
            case SCRIPT_OPCODE_5:
            case SCRIPT_OPCODE_6:
            case SCRIPT_OPCODE_7:
            case SCRIPT_OPCODE_8:
            case SCRIPT_OPCODE_9:
            case SCRIPT_OPCODE_10:
            case SCRIPT_OPCODE_11:
            case SCRIPT_OPCODE_12:
            case SCRIPT_OPCODE_13:
            case SCRIPT_OPCODE_14:
            case SCRIPT_OPCODE_15:
            case SCRIPT_OPCODE_16: // (-- n)
                vector_add(&stack->stack, (uintptr_t)make_uint8((int)opcode - (int)SCRIPT_OPCODE_1 + 1));
                break;
            case SCRIPT_OPCODE_NOP:
            case SCRIPT_OPCODE_NOP1:
            case SCRIPT_OPCODE_NOP2:
            case SCRIPT_OPCODE_NOP3:
            case SCRIPT_OPCODE_NOP4:
            case SCRIPT_OPCODE_NOP5:
            case SCRIPT_OPCODE_NOP6:
            case SCRIPT_OPCODE_NOP7:
            case SCRIPT_OPCODE_NOP8:
            case SCRIPT_OPCODE_NOP9:
            case SCRIPT_OPCODE_NOP10:
                break;
            case SCRIPT_OPCODE_DROP: // (x --)
                if(stack_size < 1) return -7;
                script_stack_pop(stack);
                break;
            case SCRIPT_OPCODE_DUP: // (x -- x x)
            {
                if(stack_size < 1) return -7; // Stack not large enough
                struct script_stack_element* top = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);
                vector_add(&stack->stack, (uintptr_t)make_stack_element(top->data, top->size));
                break;
            }
            case SCRIPT_OPCODE_EQUAL: // (x1 x2 -- (x1==x2))
            case SCRIPT_OPCODE_EQUALVERIFY:
            {
                if(stack_size < 2) return -7;

                struct script_stack_element* a = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 2);
                struct script_stack_element* b = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);

                int equal = ((a->size == b->size) && (memcmp(a->data, b->data, a->size) == 0));

                script_stack_pop(stack); // frees a
                script_stack_pop(stack); // frees b
                vector_add(&stack->stack, (uintptr_t)make_bool(equal));

                if(opcode == SCRIPT_OPCODE_EQUALVERIFY) {
                    if(equal != 0) {
                        script_stack_pop(stack); // frees result
                    } else {
                        return 0;
                    }
                }

                break;
            }
            case SCRIPT_OPCODE_MIN: // (a b -- min(a, b))
            case SCRIPT_OPCODE_MAX: // (a b -- max(a, b))
            {
                if(stack_size < 2) return -7; // Stack not large enough
                struct script_stack_element* a = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 2);
                struct script_stack_element* b = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);

                mpz_t anum;
                mpz_t bnum;

                mpz_init(anum);
                get_num(a, anum);

                mpz_init(bnum);
                get_num(b, bnum);

                mpz_t rnum;
                mpz_init(rnum);

                switch(opcode) {
                case SCRIPT_OPCODE_MIN:
                    mpz_set(rnum, mpz_cmp(anum, bnum) <= 0 ? anum : bnum);
                    break;
                case SCRIPT_OPCODE_MAX:
                    mpz_set(rnum, mpz_cmp(anum, bnum) >= 0 ? anum : bnum);
                    break;
                default:
                    assert(0);
                }

                script_stack_pop(stack); // frees b
                script_stack_pop(stack); // frees a
                vector_add(&stack->stack, (uintptr_t)make_num(rnum));

                mpz_clear(anum);
                mpz_clear(bnum);
                mpz_clear(rnum);

                break;
            }
            case SCRIPT_OPCODE_SHA256: // (x -- sha256(x))
            {
                if(stack_size < 1) return -7; // Stack not large enough
                struct script_stack_element* top = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);
                unsigned char hash[32];
                sha256(top->data, top->size, hash);
                script_stack_pop(stack); // frees top
                vector_add(&stack->stack, (uintptr_t)make_stack_element(hash, 32));
                break;
            }
            case SCRIPT_OPCODE_HASH160: // (x -- hash160(x))
            {
                if(stack_size < 1) return -7; // Stack not large enough
                struct script_stack_element* top = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);
                unsigned char hash[20];
                sha256_ripemd160(top->data, top->size, hash);
                script_stack_pop(stack); // frees top
                vector_add(&stack->stack, (uintptr_t)make_stack_element(hash, 20));
                break;
            }
            case SCRIPT_OPCODE_CODESEPARATOR:
            {
                code_separator = &script->data[pc];
                code_separator_size = script->size - pc;
                break;
            }
            case SCRIPT_OPCODE_CHECKSIG: // (sig pubkey -- bool)
            {
                if(stack_size < 2) return -7; // Stack not large enough

                struct script_stack_element* sig    = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 2);
                struct script_stack_element* pubkey = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);

                // TODO check signature encoding, no special checks generally necessary for block connecting
                // TODO check public key encoding, no special checks generally necessary for block connecting

                // Build stripped down sig script
                struct script* sig_script = NULL;
                unserialize_script(code_separator, code_separator_size, &sig_script, code_separator_size);
                assert(sig_script != NULL);

                // Remove the signature (+pushdata opcode) from the signature
                unsigned char* push_sig_data = (unsigned char*)alloca(sizeof(unsigned char) * (sig->size + 5)); // Never more than 5 bytes for the push data opcode
                size_t push_sig_data_size = 0;
                make_push_data(sig, push_sig_data, &push_sig_data_size);
                script_delete_piece(sig_script, push_sig_data, push_sig_data_size);

                // Verify signature
                int sig_check = transaction_verify_input_signature(sig->data, sig->size, pubkey->data, pubkey->size, spending_transaction, input_index, sig_script);
                assert(sig_check >= 0);

                // Push result
                script_stack_pop(stack); // frees pubkey
                script_stack_pop(stack); // frees sig
                vector_add(&stack->stack, (uintptr_t)make_bool(sig_check));
                if(sig_script != NULL) script_free(sig_script);
                break;
            }
            case SCRIPT_OPCODE_CHECKMULTISIG: // (sigs num_sigs pubkeys num_pubkeys -- bool)
            {
                if(stack_size < 1) return -7;
                
                struct script_stack_element* num_pubkeys_element = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1);
                unsigned int num_pubkeys = get_uint32(num_pubkeys_element);

                if(stack_size < (2 + num_pubkeys)) return -7;

                opcode_count += num_pubkeys;
                if(num_pubkeys == 0 || opcode_count > MAX_SCRIPT_OPCODE_COUNT) return -4;

                // Build stripped down sig script
                struct script* sig_script = NULL;
                unserialize_script(code_separator, code_separator_size, &sig_script, code_separator_size);
                assert(sig_script != NULL);

                // Remove all signatures from the script to sign
                struct script_stack_element* num_sigs_element = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 1 - num_pubkeys - 1);
                unsigned int num_sigs = get_uint32(num_sigs_element);

                if(num_sigs == 0 || num_sigs > num_pubkeys) return -4;
                if(stack_size < (2 + num_pubkeys + num_sigs)) return -7;

                unsigned char* push_sig_data = (unsigned char*)alloca(sizeof(unsigned char) * 100); // 100 is enough for all signatures, right?
                size_t push_sig_data_size = 0;

                for(size_t i = 0; i < num_sigs; i++) {
                    struct script_stack_element* sig = (struct script_stack_element*)vector_get(&stack->stack, stack_size - 2 - num_pubkeys - i - 1);
                    make_push_data(sig, push_sig_data, &push_sig_data_size);
                    script_delete_piece(sig_script, push_sig_data, push_sig_data_size);
                }

                size_t pubkey_index = stack_size - 2;
                size_t sig_index = stack_size - 2 - num_pubkeys - 1;

                int result = 1;

                while(num_sigs != 0) {
                    struct script_stack_element* sig    = (struct script_stack_element*)vector_get(&stack->stack, sig_index);
                    struct script_stack_element* pubkey = (struct script_stack_element*)vector_get(&stack->stack, pubkey_index);

                    // Verify signature
                    int sig_check = transaction_verify_input_signature(sig->data, sig->size, pubkey->data, pubkey->size, spending_transaction, input_index, sig_script);

                    if(sig_check > 0) {
                        sig_index -= 1;
                        num_sigs -= 1;
                    }

                    pubkey_index -= 1;
                    num_pubkeys -= 1;

                    if(num_sigs > num_pubkeys) {
                        result = 0;
                        break;
                    }
                }

                // pop everything off the stack
                size_t total_stack = num_pubkeys + num_sigs + 2;
                for(size_t i = 0; i < total_stack; i++) script_stack_pop(stack);
                stack_size -= total_stack;

                // due to an early bug, we have to account for the 0 opcode
                if(stack_size < 1) return -7;

                // bitcore core seems to accept the transaction if the leading opcode is non-zero, but
                // won't accept it to memory pool. we'll accept everything.
                script_stack_pop(stack);
                vector_add(&stack->stack, (uintptr_t)make_bool(result));

                if(sig_script != NULL) script_free(sig_script);
                break;
            }
            default:
                printf("unknown opcode %d (%02X)\n", (int)opcode, (int)opcode);
                assert(0);
            }
        }

        // Enforce stack size limits
        if(vector_count(&stack->stack) > MAX_STACK_HEIGHT) return -6;
    };

    return 1;
}

static int script_delete_piece(struct script* script, unsigned char* piece, size_t piece_size)
{
    size_t count = 0;
    void* r = memmem(script->data, script->size, piece, piece_size);
    while(r != NULL) {
        void* end = r + piece_size;
        size_t end_position = (uintptr_t)end - (uintptr_t)script->data;

        size_t remaining = script->size - end_position;
        memcpy(r, r + piece_size, remaining);
        script->size -= piece_size;
        count += 1;

        r = memmem(script->data, script->size, piece, piece_size);
    };

    return count;
}

size_t serialize_script(unsigned char* out, struct script const* in, size_t script_length)
{
    assert(script_size(in) >= script_length);
    return serialize_bytes(out, in->data, script_length);
}

size_t serialize_script_for_signing(unsigned char* out, struct script const* in)
{
    size_t offset = 0;

    size_t start = 0;
    size_t end = 0;

    while(start < in->size && end < in->size) {
        enum script_opcode opcode = SCRIPT_OPCODE_INVALID;
        size_t opcode_size = 0;
        int r = next_opcode(in, end, &opcode, &opcode_size, NULL, NULL);
        assert(r != 0);

        if(opcode == SCRIPT_OPCODE_CODESEPARATOR) {
            offset += serialize_bytes(out == NULL ? NULL : &out[offset], &in->data[start], end - start);
            start = end + opcode_size;
        }

        end += opcode_size;
    }

    if(start < in->size) {
        offset += serialize_bytes(out == NULL ? NULL : &out[offset], &in->data[start], in->size - start);
    }

    return offset;
}

size_t unserialize_script(unsigned char const* in, size_t in_size, struct script** out, size_t script_size)
{
    size_t offset = 0;
    if(script_size > in_size) return 0;

    struct script* script = (struct script*)malloc(sizeof(struct script));
    script->size = script_size;
    script->data = (unsigned char*)malloc(sizeof(unsigned char) * script_size);
    offset += unserialize_bytes(&in[offset], in_size - offset, script->data, script_size);
    *out = script;
    return offset;
}

