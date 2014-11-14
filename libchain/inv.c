#include <string.h>
#include <unistd.h>

#include "inv.h"
#include "serialize.h"
#include "util.h"

size_t serialize_inv(unsigned char* out, struct inv const* in)
{
    size_t offset = 0;

    offset += serialize_uint32(out == NULL ? NULL : &out[offset], in->type);
    offset += serialize_bytes(out == NULL ? NULL : &out[offset], in->hash, 32);

    return offset;
}

size_t unserialize_inv(unsigned char const* in, size_t in_size, struct inv* out)
{
    size_t offset = 0;

    if(in_size < sizeof(struct inv)) return 0;

    zero(out);
    offset += unserialize_uint32(&in[offset], in_size - offset, out == NULL ? NULL : &out->type);
    offset += unserialize_bytes(&in[offset], in_size - offset, out == NULL ? NULL : out->hash, 32);
    return offset;
}

