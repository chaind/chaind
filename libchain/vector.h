#ifndef __VECTOR_H
#define __VECTOR_H

#include <stdio.h>
#include <stdlib.h>
 
struct vector {
    uintptr_t* data;
    size_t size;
    size_t count;
};

typedef struct vector vector;

static inline void vector_init(vector *v)
{
	v->data = NULL;
	v->size = 0;
	v->count = 0;
}
 
static inline int vector_count(vector *v)
{
	return v->count;
}

static inline uintptr_t* vector_data(vector *v)
{
	return v->data;
}
 
static inline void vector_add(vector *v, uintptr_t e)
{
	if (v->size == 0) {
		v->size = 8;
		v->data = (uintptr_t*)malloc(sizeof(uintptr_t) * v->size);
	} else if (v->size == v->count) {
		v->size <<= 1;
		v->data = (uintptr_t*)realloc(v->data, sizeof(void*) * v->size);
	}
 
	v->data[v->count] = e;
	v->count += 1;
}

static inline uintptr_t vector_pop(vector *v)
{
    if(v->count > 0) return v->data[--v->count];
    return 0;
} 

static inline void vector_set(vector *v, size_t index, uintptr_t e)
{
	if (index >= v->count) return;
	v->data[index] = e;
}
 
static inline uintptr_t vector_get(vector *v, size_t index)
{
	if (index >= v->count) return 0;
	return v->data[index];
}

static inline void vector_delete(vector *v, size_t index)
{
	if (index >= v->count) return;
 
    for(size_t i = index; i < (v->count - 1); i++) {
        v->data[i] = v->data[i + 1];
    }

    v->count -= 1;
}
 
static inline void vector_free(vector *v)
{
	free(v->data);
}

#endif /* __VECTOR_H */

