#ifndef __SERIALIZE_H
#define __SERIALIZE_H

#include <stdint.h>

#define NETWORK_MESSAGE_OVERHEAD 24
#define NETWORK_MESSAGE_COMMAND_OFFSET 4
#define NETWORK_MESSAGE_COMMAND_SIZE 12
#define NETWORK_MESSAGE_CHECKSUM_SIZE 4

struct network_address;

// serialize_network_message will write exactly NETWORK_MESSAGE_OVERHEAD bytes to out
size_t serialize_network_message(unsigned char* out, char const* command, unsigned char const* payload, size_t payload_size);
size_t unserialize_network_message(unsigned char* in, size_t in_size, unsigned char* command, unsigned char** payload, size_t* payload_size);

size_t serialize_bytes(unsigned char* out, unsigned char const* bytes, size_t size);
size_t serialize_string(unsigned char* out, char const* s);
size_t serialize_network_address(unsigned char* out, struct network_address const* address, uint64_t services, int with_timestamp);
size_t serialize_variable_uint(unsigned char* out, uint64_t v);
size_t serialize_uint8(unsigned char* out, unsigned char v);
size_t serialize_uint16(unsigned char* out, unsigned short v);
size_t serialize_uint32(unsigned char* out, unsigned int v);
size_t serialize_uint64(unsigned char* out, uint64_t v);

size_t unserialize_bytes(unsigned char const* in, size_t in_size, unsigned char* out, size_t size);
size_t unserialize_string(unsigned char const* in, size_t in_size, char* out, size_t* out_size);
size_t unserialize_network_address(unsigned char const* in, size_t in_size, struct network_address* address, uint64_t* services, unsigned int* timestamp);
size_t unserialize_variable_uint(unsigned char const* in, size_t in_size, uint64_t* v);
size_t unserialize_uint8(unsigned char const* in, size_t in_size, unsigned char* v);
size_t unserialize_uint16(unsigned char const* in, size_t in_size, unsigned short* v);
size_t unserialize_uint32(unsigned char const* in, size_t in_size, unsigned int* v);
size_t unserialize_uint64(unsigned char const* in, size_t in_size, uint64_t* v);

#endif /* __SERIALIZE_H */
