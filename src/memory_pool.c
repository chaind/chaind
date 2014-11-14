#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Judy.h>
#include <libchain/libchain.h>

#include "memory_pool.h"

struct memory_pool {
    size_t default_size;
    size_t maximum_size;
};

struct memory_pool* memory_pool_create(size_t default_size, size_t maximum_size)
{
    assert(is_power_of_2(default_size));
    assert(is_power_of_2(maximum_size));
    struct memory_pool* mempool = (struct memory_pool*)malloc(sizeof(struct memory_pool));

    zero(mempool);
    mempool->default_size = default_size;
    mempool->maximum_size = maximum_size;

    return mempool;
}

void memory_pool_destroy(struct memory_pool* mempool)
{
    free(mempool);
}

int memory_pool_has_inv(struct memory_pool* mempool, struct inv const* inv)
{
    return 0;
}

