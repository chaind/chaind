#ifndef __SCRIPT_H
#define __SCRIPT_H

#include "script_opcodes.h"

struct script;
struct script_stack;
struct transaction;

struct script* script_static_empty();
struct script* script_clone(struct script*);
void script_free(struct script*);
unsigned char* script_data(struct script*);
size_t script_size(struct script const*);
int script_is_p2sh(struct script const*);
int script_is_push_only(struct script const*);
unsigned int script_legacy_sigop_count(struct script const*, int accurate);
unsigned int script_p2sh_sigop_count(struct script const* output_script, struct script const* spend_script);

// Bitcoin Core calls "coins" the scriptPubKey and calls "spend" the scriptSig.
// Those names aren't quite right any more, though.
int script_verify(struct script* coins, struct transaction* spending_transaction, size_t input_index); 

size_t serialize_script(unsigned char* out, struct script const* in, size_t script_length);
size_t serialize_script_for_signing(unsigned char* out, struct script const* in);
size_t unserialize_script(unsigned char const* in, size_t in_size, struct script** out, size_t script_size);

#endif /* __SCRIPT_H */
