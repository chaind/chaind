#ifndef __DEQUE_H
#define __DEQUE_H

#include <stdio.h>
#include <stdlib.h>
 
#include <Judy.h>

struct deque {
    size_t left;
    size_t right;
    void*  list;
};

typedef struct deque deque;

static inline void deque_init(deque *v)
{
    v->left = 0x8000000000000000ULL;
    v->right = 0x8000000000000000ULL;
    v->list = NULL;
}
 
static inline int deque_count(deque *v)
{
	return v->right - v->left;
}

 
static inline uintptr_t deque_peekright(deque *v)
{
    Word_t index = (Word_t)v->right - 1;
    uintptr_t* p;
    JLG(p, v->list, index);
	return *p;
}

static inline uintptr_t deque_peekleft(deque *v)
{
    Word_t index = (Word_t)v->left;
    uintptr_t* p;
    JLG(p, v->list, index);
	return *p;
}
 
static inline uintptr_t deque_popright(deque *v)
{
    int rc;
    Word_t index = (Word_t)v->right - 1;
    uintptr_t* p, e;
    JLG(p, v->list, index);
    e = *p;
    JLD(rc, v->list, index);
    v->right -= 1;
	return e;
}
 
static inline uintptr_t deque_popleft(deque *v)
{
    int rc;
    Word_t index = (Word_t)v->left;
    uintptr_t* p, e;
    JLG(p, v->list, index);
    e = *p;
    JLD(rc, v->list, index);
    v->left += 1;
	return e;
}
 
static inline void deque_appendright(deque *v, uintptr_t e)
{
    Word_t index = (Word_t)v->right;
    uintptr_t* p;
    JLI(p, v->list, index);
    *p = e;
    v->right += 1;
}

static inline void deque_appendleft(deque *v, uintptr_t e)
{
    Word_t index = (Word_t)v->left - 1;
    uintptr_t* p;
    JLI(p, v->list, index);
    *p = e;
    v->left -= 1;
}

static inline void deque_free(deque *v)
{
    int rc;
    JLFA(rc, v->list);
}

#endif /* __DEQUE_H */

