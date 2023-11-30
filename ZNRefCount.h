//
//  ZNRefCount.h
//  zinc
//
//  Created by Aaron Voisine on 4/16/21.
//

#ifndef ZNRefCount_h
#define ZNRefCount_h

#include <stdlib.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

// simple reference counting for any pointer type
//
// example:
//
// struct myStruct *myPtr, *otherPtr;
//
// myPtr = zn_ref_new(sizeof(*myPtr), myStructFree); // starts with a reference count of 1
//
// otherPtr = myPtr;
// zn_ref_retain(otherPtr); // increment reference count
//
// zn_ref_release(myPtr);   // decrement reference count
// myPtr = NULL;
//
// zn_ref_relase(otherPtr); // reference count is now 0, myStructFree() will be called
// otherPtr = NULL;
//
// ...
//
// void myStructFree(struct myStruct *myPtr)
// {
//     // free memory allocated for members of myStruct here
//
//     zn_ref_free(myPtr); // free memory allocated by zn_ref_new()
// }

// free_func() may be NULL
#define zn_ref_new(size, free_func) _ZNRefNew(size, free_func)

#define zn_ref_retain(ptr) (++((_ZNRef *)(ptr))[-1].count, (ptr))

// ptr may be NULL
#define zn_ref_release(ptr) do {\
    _ZNRef *_zn_r = (_ZNRef *)(ptr);\
    if (_zn_r && --_zn_r[-1].count == 0) _zn_r[-1].free(_zn_r);\
} while (0)

// call this at the end of free_frunc() passed into zn_ref_new()
#define zn_ref_free(ptr) _ZNRefFree(ptr)

// private - struct/functions

typedef struct _ZNRefStruct {
    void (*free)(void *);
    unsigned count;
} _ZNRef;

static void _ZNRefFree(void *ptr)
{
    free((_ZNRef *)ptr - 1);
}

static void *_ZNRefNew(size_t size, void (*free_func)(void *))
{
    _ZNRef *ptr = (_ZNRef *)calloc(1, size + sizeof(_ZNRef)) + 1;

    assert(ptr != NULL);
    ptr[-1].free = (free_func) ? free_func : _ZNRefFree;
    zn_ref_retain(ptr);
    return ptr;
}

#ifdef __cplusplus
}
#endif

#endif // ZNRefCount_h
