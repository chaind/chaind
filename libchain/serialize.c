#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hashes.h"
#include "network.h"
#include "serialize.h"

static unsigned char const NETWORK_MAGIC[] = { 0xF9, 0xBE, 0xB4, 0xD9 };

size_t serialize_uint8(unsigned char* out, unsigned char v)
{
    if(out != NULL) {
        out[0] = v & 0xFF;
    }
    return 1;
}

size_t serialize_uint16(unsigned char* out, unsigned short v)
{
    if(out != NULL) {
        out[0] =  v & 0xFF;
        out[1] = (v & 0xFF00) >> 8;
    }
    return 2;
}

size_t serialize_uint32(unsigned char* out, unsigned int v)
{
    if(out != NULL) {
        out[0] =  v & 0x000000FF;
        out[1] = (v & 0x0000FF00) >> 8;
        out[2] = (v & 0x00FF0000) >> 16;
        out[3] = (v & 0xFF000000) >> 24;
    }
    return 4;
}

size_t serialize_uint64(unsigned char* out, uint64_t v)
{
    if(out != NULL) {
        out[0] =  v & 0x00000000000000FFLL;
        out[1] = (v & 0x000000000000FF00LL) >> 8;
        out[2] = (v & 0x0000000000FF0000LL) >> 16;
        out[3] = (v & 0x00000000FF000000LL) >> 24;
        out[4] = (v & 0x000000FF00000000LL) >> 32;
        out[5] = (v & 0x0000FF0000000000LL) >> 40;
        out[6] = (v & 0x00FF000000000000LL) >> 48;
        out[7] = (v & 0xFF00000000000000LL) >> 56;
    }
    return 8;
}

size_t serialize_network_address(unsigned char* out, struct network_address const* address, uint64_t services, int with_timestamp)
{
    size_t offset = 0;

    if(with_timestamp) {
        offset += serialize_uint32(out == NULL ? NULL : &out[offset], (unsigned int)time(NULL));
    }

    offset += serialize_uint64(out == NULL ? NULL : &out[offset], services);

    if(out != NULL) {
        if(address != NULL) {
            if(address->type == NETWORK_ADDRESS_TYPE_IPV4) {
                memset(&out[0], 0, 16);
                out[10] = 0xFF;
                out[11] = 0xFF;
                serialize_uint32(&out[12], address->ipv4.addr.s_addr);
            } else if(address->type == NETWORK_ADDRESS_TYPE_IPV6) {
                memcpy(&out[0], (void *)&address->ipv6.addr, 16);
            }

            // Port is serialized big-endian
            unsigned short port = ntohs(address->sin_port);
            out[16] = (port & 0xFF00) >> 8;
            out[17] = port & 0xFF;
        } else {
            memset(&out[0], 0, 18);
            out[11] = 0xFF;
            out[12] = 0xFF;
        }
    }

    offset += 18;

    return offset;
}

size_t serialize_variable_uint(unsigned char* out, uint64_t v)
{
    if(v < 0xFD) {
        if(out != NULL) {
            out[0] = (unsigned char)(v & 0xFF);
        }
        return 1;
    } else if(v < 0xFFFF) {
        if(out != NULL) {
            out[0] = 0xFD;
            serialize_uint16(&out[1], (unsigned short)(v & 0xFFFF));
        }
        return 3;
    } else if(v < 0xFFFFFFFFULL) {
        if(out != NULL) {
            out[0] = 0xFE;
            serialize_uint32(&out[1], (unsigned int)(v & 0xFFFFFFFF));
        }
        return 5;
    } else {
        if(out != NULL) {
            out[0] = 0xFF;
            serialize_uint64(&out[1], v);
        }
        return 9;
    }
}

size_t serialize_bytes(unsigned char* out, unsigned char const* bytes, size_t size)
{
    size_t offset = 0;
    if(out != NULL) memcpy(&out[offset], bytes, size);
    offset += size;
    return offset;
}

size_t serialize_string(unsigned char* out, char const* s)
{
    size_t offset = 0;
    size_t len = strlen(s);
    offset += serialize_variable_uint(out == NULL ? NULL : &out[offset], (uint64_t)len);
    offset += serialize_bytes(out == NULL ? NULL : &out[offset], (unsigned char*)s, strlen(s));
    return offset;
}

size_t serialize_network_message(unsigned char* out, char const* command, unsigned char const* payload, size_t payload_size)
{
    size_t offset = 0;

    if(out != NULL) {
        // Magic
        memcpy(&out[offset], NETWORK_MAGIC, sizeof(NETWORK_MAGIC));
        offset += sizeof(NETWORK_MAGIC);

        // Command
        memset(&out[offset], 0, NETWORK_MESSAGE_COMMAND_SIZE);
        memcpy(&out[offset], command, strlen(command));
        offset += NETWORK_MESSAGE_COMMAND_SIZE;

        // Payload size
        offset += serialize_uint32(&out[offset], (unsigned int)payload_size);

        // Payload checksum
        unsigned char h[32];
        sha256_sha256(payload, payload_size, h);
        memcpy(&out[offset], h, NETWORK_MESSAGE_CHECKSUM_SIZE);
        offset += NETWORK_MESSAGE_CHECKSUM_SIZE;
    }

    return offset;
}

size_t unserialize_uint8(unsigned char const* in, size_t in_size, unsigned char* v)
{
    if(in_size < 1) return 0;
    if(v != NULL) *v = in[0];
    return 1;
}

size_t unserialize_uint16(unsigned char const* in, size_t in_size, unsigned short* v)
{
    if(in_size < 2) return 0;
    if(v != NULL) *v = (in[0] | (in[1] << 8));
    return 2;
}

size_t unserialize_uint32(unsigned char const* in, size_t in_size, unsigned int* v)
{
    if(in_size < 4) return 0;
    if(v != NULL) *v = (in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24));
    return 4;
}

size_t unserialize_uint64(unsigned char const* in, size_t in_size, uint64_t* v)
{
    if(in_size < 8) return 0;
    if(v != NULL) *v = (in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24)
                    | ((uint64_t)in[4] << 32) | ((uint64_t)in[5] << 40) | ((uint64_t)in[6] << 48)
                    | ((uint64_t)in[7] << 56));
    return 8;
}

size_t unserialize_variable_uint(unsigned char const* in, size_t in_size, uint64_t* v)
{
    if(in_size < 1) return 0;
    unsigned char c = in[0];
    if(c < 0xFD) {
        if(v != NULL) *v = (uint64_t)c;
        return 1;
    } else if(c == 0xFD) {
        if(in_size < 3) return 0;
        unsigned short int vv;
        unserialize_uint16(&in[1], in_size - 1, &vv);
        if(v != NULL) *v = (uint64_t)vv;
        return 3;
    } else if(c == 0xFE) {
        if(in_size < 5) return 0;
        unsigned int vv;
        unserialize_uint32(&in[1], in_size - 1, &vv);
        if(v != NULL) *v = (uint64_t)vv;
        return 5;
    } else {
        if(in_size < 9) return 0;
        unserialize_uint64(&in[1], in_size - 1, v);
        return 9;
    }
}

size_t unserialize_network_message(unsigned char* in, size_t in_size, unsigned char* command, unsigned char** payload, size_t* payload_size)
{
    size_t offset = 0;

    // Magic 
    if(in_size < sizeof(NETWORK_MAGIC)) return offset;
    if(memcmp(&in[offset], NETWORK_MAGIC, sizeof(NETWORK_MAGIC)) != 0) return -1;
    offset += sizeof(NETWORK_MAGIC);

    // Command
    if((in_size - offset) < NETWORK_MESSAGE_COMMAND_SIZE) return offset;
    if(command != NULL) {
        memcpy(command, &in[offset], NETWORK_MESSAGE_COMMAND_SIZE);
    }
    offset += NETWORK_MESSAGE_COMMAND_SIZE;

    // Payload size
    unsigned int _payload_size;
    if((in_size - offset) < 4) return offset;
    if(payload_size != NULL) {
        offset += unserialize_uint32(&in[offset], in_size - offset, &_payload_size);
        *payload_size = _payload_size;
    } else {
        offset += 4;
    }

    // Checksum
    if((in_size - offset) < NETWORK_MESSAGE_CHECKSUM_SIZE) return offset;
    unsigned char checksum[NETWORK_MESSAGE_CHECKSUM_SIZE];
    memcpy(checksum, &in[offset], NETWORK_MESSAGE_CHECKSUM_SIZE);
    offset += NETWORK_MESSAGE_CHECKSUM_SIZE;

    // Payload
    if((in_size - offset) < _payload_size) return offset;
    if(payload != NULL) {
        unsigned char h[32];
        *payload = &in[offset];
        sha256_sha256(*payload, *payload_size, h);
        if(memcmp(h, checksum, NETWORK_MESSAGE_CHECKSUM_SIZE) != 0) return offset;
    }
    offset += _payload_size;

    return offset;
}

size_t unserialize_bytes(unsigned char const* in, size_t in_size, unsigned char* out, size_t size)
{
    if(in_size < size) return 0;

    if(out != NULL) {
        memcpy(out, in, size);
    }

    return size;
}

size_t unserialize_string(unsigned char const* in, size_t in_size, char* out, uint64_t* out_size)
{
    size_t offset = 0;
    uint64_t o;

    uint64_t c;
    offset += unserialize_variable_uint(in, in_size, &c);
    if(offset == 0) return 0;

    // out_size cannot be NULL
    o = *out_size;
    *out_size = c;

    // if we can't read the whole string then we read nothing
    if((offset + c) > in_size) return 0;

    if(out != NULL) {
        size_t x = (c < o) ? c : o;
        memcpy(out, &in[offset], x);
    }

    return offset + c;
}

size_t unserialize_network_address(unsigned char const* in, size_t in_size, struct network_address* address, uint64_t* services, unsigned int* timestamp)
{
    size_t offset = 0;

    if(timestamp != NULL) {
        offset += unserialize_uint32(&in[offset], in_size - offset, timestamp);
    }

    offset += unserialize_uint64(&in[offset], in_size - offset, services == NULL ? NULL : services);

    if(address != NULL) {
        if(memcmp(&in[offset], "\0\0\0\0\0\0\0\0\0\0\xFF\xFF", 12) == 0) {
            unserialize_uint32(&in[offset + 12], in_size - offset, &address->ipv4.addr.s_addr);
            address->type = NETWORK_ADDRESS_TYPE_IPV4;
        } else {
            memcpy((void *)&address->ipv6.addr, &in[offset], 16);
            address->type = NETWORK_ADDRESS_TYPE_IPV6;
        }

        // Port is serialized big-endian
        address->sin_port = htons(in[17] | (in[16] << 8));
    }

    offset += 18;

    return offset;
}

