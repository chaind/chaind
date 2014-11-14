#ifndef __MEMORY_POOL_H
#define __MEMORY_POOL_H

struct inv;
struct memory_pool;

struct memory_pool* memory_pool_create(size_t default_size, size_t maximum_size);
void memory_pool_destroy(struct memory_pool*);
int memory_pool_has_inv(struct memory_pool*, struct inv const*);

#endif
