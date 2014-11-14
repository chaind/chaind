#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <secp256k1.h>

#include "crypto.h"
#include "util.h"

void crypto_init()
{
    secp256k1_start(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
}

void crypto_deinit()
{
    secp256k1_stop();
}

int crypto_is_valid_public_key(unsigned char const* public_key, size_t public_key_size)
{
    return secp256k1_ecdsa_pubkey_verify(public_key, public_key_size);
}

int crypto_verify_signature(unsigned char* signature, size_t signature_size, 
                            unsigned char* public_key, size_t public_key_size,
                            unsigned char* hash)
{
    size_t sig_str_size = sizeof(char) * (2 * signature_size + 1);
    char* sig_str = (char*)alloca(sig_str_size);
    memset(sig_str, 0, sig_str_size);
    __bytes_to_hexstring(signature, signature_size, sig_str, 2 * signature_size + 1, 0);

    size_t pubkey_str_size = sizeof(char) * (2 * public_key_size + 1);
    char* pubkey_str = (char*)alloca(pubkey_str_size);
    memset(pubkey_str, 0, pubkey_str_size);
    __bytes_to_hexstring(public_key, public_key_size, pubkey_str, 2 * public_key_size + 1, 0);

    bytes_to_hexstring(hash, 32, hash_str, 0);

    int result = secp256k1_ecdsa_verify(hash, 32, signature, signature_size, public_key, public_key_size);

#if 0
    printf("verifying signature for hash %s\n", hash_str);
    printf("\tsignature %s\n", sig_str);
    printf("\tpublic key %s\n", pubkey_str);
    printf("\t-> result %d\n", result);
#endif

    return result;
}

