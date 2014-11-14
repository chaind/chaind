#ifndef __HASHES_H
#define __HASHES_H

extern unsigned char const HASH_ZERO[32];

void sha256(unsigned char const* in, size_t in_size, unsigned char* out);
void ripemd160(unsigned char const* in, size_t in_size, unsigned char* out);

static inline void sha256_sha256(unsigned char const* in, size_t in_size, unsigned char* out)
{
    unsigned char h1[32];
    sha256(in, in_size, h1);
    sha256(h1, 32, out);
}

static inline unsigned int sha256_first4(unsigned char const* in, size_t in_size)
{
    unsigned char h[32];
    sha256(in, in_size, h);
    return (h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24));
}

static inline void sha256_ripemd160(unsigned char const* in, size_t in_size, unsigned char* out)
{
    unsigned char h1[32];
    sha256(in, in_size, h1);
    ripemd160(h1, 32, out);
}

#endif /* __HASHES_H */
