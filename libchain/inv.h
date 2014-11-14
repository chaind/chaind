#ifndef __INV_H
#define __INV_H

#define INV_HASH_SIZE 32

enum INV_TYPE {
    INV_TYPE_ERROR = 0,
    INV_TYPE_TX,
    INV_TYPE_BLOCK,
};

struct inv {
    enum INV_TYPE type;
    unsigned char hash[INV_HASH_SIZE];
};

size_t serialize_inv(unsigned char* out, struct inv const* in);
size_t unserialize_inv(unsigned char const* in, size_t in_size, struct inv* out);

#endif /* __INV_H */
