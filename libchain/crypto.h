#ifndef __CRYPTO_H
#define __CRYPTO_H

// Because we use libsecp256k1, you must call crypto_init() in your application before
// using any other crypto functions.
void crypto_init();
void crypto_deinit();

int crypto_is_valid_public_key(unsigned char const*, size_t);

// Hash must be 32 bytes
int crypto_verify_signature(unsigned char* signature, size_t signature_size, 
                            unsigned char* public_key, size_t public_key_size,
                            unsigned char* hash);

#endif /* __CRYPTO_H */
