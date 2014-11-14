#ifndef __UTIL_H
#define __UTIL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define bytes_to_hexstring(bytes, c, varname, reverse) \
    char varname[c*2+1] = { 0, }; \
    __bytes_to_hexstring(bytes, c, varname, c*2, reverse); 

#define hexstring_to_bytes(str, n, varname, reverse) \
    size_t varname##__s = strlen(str); \
    assert(((n)*2) == varname##__s); \
    unsigned char varname[n] = { 0, }; \
    __hexstring_to_bytes(str, varname##__s, varname, n, reverse); 

static inline void __bytes_to_hexstring(unsigned char const* bytes, size_t in_size, char* out, size_t out_size, int reverse)
{
    static char const* const B = "0123456789abcdef";
    size_t offset = 0;
    for(size_t i = 0; i < in_size && offset + 2 <= out_size; i++, offset += 2) {
        unsigned char v = bytes[(reverse != 0) ? (in_size - i - 1) : i];

        out[offset + 0] = B[((v & 0xf0) >> 4)];
        out[offset + 1] = B[v & 0x0f];
    }
}

static inline void __hexstring_to_bytes(char const* in, size_t in_size, unsigned char* out, size_t out_size, int reverse)
{
    // TODO: support odd length inputs
    size_t offset = 0;
    unsigned char a, b;
    unsigned int c;
    for(size_t i = 0; i + 2 <= in_size && offset < out_size; i += 2, offset++) {
        size_t i2 = (reverse != 0) ? (in_size - i - 2) : i;
        
        c = (int)in[i2 + 0];
        if(c >= (unsigned int)'0' && c <= (unsigned int)'9') a = c - (unsigned int)'0';
        else a = ((c & ~0x20) - (unsigned int)'A') + 10;

        c = (int)in[i2 + 1];
        if(c >= (unsigned int)'0' && c <= (unsigned int)'9') b = c - (unsigned int)'0';
        else b = ((c & ~0x20) - (unsigned int)'A') + 10;

        out[offset] = (a << 4) | b;
    }
}

static inline int is_hex_string(char const* s, size_t len)
{
    for(size_t i = 0; i < len; i++) {
        if((int)s[i] < (int)'0' || ((int)s[i] & ~0x20) > (int)'F') return 0;
    }
    return 1;
}

static inline int is_power_of_2(uint64_t v)
{
    return (v != 0 && ((v & (v - 1)) == 0));
}

static inline void* memdup(void const* src, size_t size)
{
    void* r = (void*)malloc(size);
    memcpy(r, src, size);
    return r;
}

#define zero(x) memset(x, 0, sizeof(*(x)))

#define assert_pointer(x) (assert(x != NULL))
#define _assert_compile_time(t,s) typedef char __compile_time_assert_##s[(t)?1:-1]
#define assert_compile_time(t) _assert_compile_time(t,__LINE__)

uint64_t microtime(void);

#ifndef MAX
#  define MAX(a,b) (((a) < (b)) ? (b) : (a))
#endif

#ifndef MIN
#  define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#include <gmp.h>

void bits_to_target(unsigned int bits, mpz_t);
unsigned int target_to_bits(mpz_t target);

#endif /* __UTIL_H */ 
