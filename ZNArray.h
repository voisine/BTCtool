//
//  ZNArray.h
//  zinc
//
//  Created by Aaron Voisine on 12/22/20.
//

#ifndef ZNArray_h
#define ZNArray_h

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

// growable arrays with type checking
//
// example:
//
// char *myArray = zn_array_new(sizeof(char), 3); // initialize myArray with an initial capacity of 3 items
//
// zn_array_add(myArray, 'a');                    // add 'a' to myArray
// zn_array_add_array(myArray, "bcd", 3);         // add 'b', 'c', 'd' to myArray (capacity is auto-increased)
// zn_array_set_count(myArray, 5);                // myArray now has 5 items: 'a', 'b', 'c', 'd', '\0'
// zn_array_rm(myArray, 3);                       // remove 'd' from myArray
// zn_array_rm_last(myArray);                     // remove '\0' from end of myArray
// zn_array_insert(myArray, 0, 'x');              // insert 'x' at start of myArray
// zn_array_insert_array(myArray, 1, "yz", 2);    // insert 'y', 'z' after 'x'
//
// for (int i = 0; i < zn_array_count(myArray); i++) {
//     printf("%c, ", myArray[i]);                // x, y, z, a, b, c,
// }
//
// zn_array_rm_range(myArray, 3, 3);              // remove 'a', 'b', 'c' from end of myArray
// zn_array_clear(myArray);                       // myArray is now empty
// zn_array_free(myArray);                        // free memory allocated for myArray
//
// NOTE: when new items are added to an array past its current capacity, its memory location may change

#define zn_array_new(item_size, capacity) _ZNArrNew(item_size, capacity)

#define zn_array_capacity(array) (((size_t *)(array))[-2])

#define zn_array_set_capacity(array, capacity) do {\
    size_t _zn_p = (capacity);\
    assert((array) != NULL);\
    assert(_zn_p >= zn_array_count(array));\
    size_t *_zn_a = (size_t *)realloc((size_t *)(array) - 2, _zn_p*sizeof(*(array)) + sizeof(size_t)*2) + 2;\
    assert(_zn_a - 2 != NULL);\
    memset((char *)_zn_a + zn_array_capacity(_zn_a)*sizeof(*(array)), 0,\
           (_zn_p - zn_array_capacity(_zn_a))*sizeof(*(array)));\
    zn_array_capacity(_zn_a) = _zn_p;\
    if ((array) != (void *)_zn_a) (array) = (void *)_zn_a;\
} while (0)

#define zn_array_count(array) (((size_t *)(array))[-1])

#define zn_array_set_count(array, count) do {\
    size_t _zn_c = (count);\
    assert((array) != NULL);\
    if (_zn_c > zn_array_capacity(array))\
        zn_array_set_capacity(array, _zn_c);\
    if (_zn_c < zn_array_count(array))\
        memset((array) + _zn_c, 0, (zn_array_count(array) - _zn_c)*sizeof(*(array)));\
    zn_array_count(array) = _zn_c;\
} while (0)

#define zn_array_add(array, item) do {\
    assert((array) != NULL);\
    if (zn_array_count(array) + 1 > zn_array_capacity(array))\
        zn_array_set_capacity(array, (zn_array_capacity(array) + 1)*3/2);\
    (array)[zn_array_count(array)++] = (item);\
} while (0)

#define zn_array_add_array(array, other_array, count) do {\
    size_t _zn_c = (count);\
    assert((array) != NULL);\
    assert((other_array) != NULL || _zn_c == 0);\
    if (zn_array_count(array) + _zn_c > zn_array_capacity(array))\
        zn_array_set_capacity(array, (zn_array_count(array) + _zn_c)*3/2);\
    memcpy((array) + zn_array_count(array), (other_array), _zn_c*sizeof(*(array)));\
    zn_array_count(array) += _zn_c;\
} while (0)

#define zn_array_insert(array, index, item) do {\
    size_t _zn_i = (index);\
    assert((array) != NULL);\
    assert(_zn_i <= zn_array_count(array));\
    if (zn_array_count(array) + 1 > zn_array_capacity(array))\
        zn_array_set_capacity(array, (zn_array_capacity(array) + 1)*3/2);\
    memmove((array) + _zn_i + 1, (array) + _zn_i, (zn_array_count(array) - _zn_i)*sizeof(*(array)));\
    (array)[_zn_i] = (item);\
    zn_array_count(array)++;\
} while (0)

#define zn_array_insert_array(array, index, other_array, count) do {\
    size_t _zn_i = (index), _zn_c = (count);\
    assert((array) != NULL);\
    assert(_zn_i <= zn_array_count(array));\
    assert((other_array) != NULL || _zn_c == 0);\
    if (zn_array_count(array) + _zn_c > zn_array_capacity(array))\
        zn_array_set_capacity(array, (zn_array_count(array) + _zn_c)*3/2);\
    memmove((array) + _zn_i + _zn_c, (array) + _zn_i, (zn_array_count(array) - _zn_i)*sizeof(*(array)));\
    memcpy((array) + _zn_i, (other_array), _zn_c*sizeof(*(array)));\
    zn_array_count(array) += _zn_c;\
} while (0)

#define zn_array_rm(array, index) do {\
    size_t _zn_i = (index);\
    assert((array) != NULL);\
    assert(_zn_i < zn_array_count(array));\
    zn_array_count(array)--;\
    memmove((array) + _zn_i, (array) + _zn_i + 1, (zn_array_count(array) - _zn_i)*sizeof(*(array)));\
    memset((array) + zn_array_count(array), 0, sizeof(*(array)));\
} while (0)

#define zn_array_rm_range(array, index, count) do {\
    size_t _zn_i = (index), _zn_c = (count);\
    assert((array) != NULL);\
    assert(_zn_i < zn_array_count(array));\
    assert(_zn_i + _zn_c <= zn_array_count(array));\
    zn_array_count(array) -= _zn_c;\
    memmove((array) + _zn_i, (array) + _zn_i + _zn_c, (zn_array_count(array) - _zn_i)*sizeof(*(array)));\
    memset((array) + zn_array_count(array), 0, _zn_c*sizeof(*(array)));\
} while (0)

#define zn_array_rm_last(array) do {\
    assert((array) != NULL);\
    if (zn_array_count(array) > 0)\
        memset((array) + --zn_array_count(array), 0, sizeof(*(array)));\
} while (0)

#define zn_array_clear(array) do {\
    assert((array) != NULL);\
    memset((array), 0, zn_array_count(array)*sizeof(*(array)));\
    zn_array_count(array) = 0;\
} while (0)

// function signature for apply_func is 'void apply_func(void *info, array_type_t item)'
#define zn_array_apply(array, info, apply_func) do {\
    size_t _zn_i = 0;\
    assert((array) != NULL);\
    assert((apply_func) != NULL);\
    while (_zn_i < zn_array_count(array))\
        (apply_func)((info), (array)[_zn_i++]);\
} while (0)

#define zn_array_free(array) do {\
    assert((array) != NULL);\
    free((size_t *)(array) - 2);\
} while (0)

// private - functions

static void *_ZNArrNew(size_t item_size, size_t capacity)
{
    size_t *array;
    
    if (capacity < 2) capacity = 2;
    array = calloc(1, item_size*capacity + sizeof(*array)*2);
    assert(array != NULL);
    array[0] = capacity;
    return array + 2;
}

#ifdef __cplusplus
}
#endif

#endif // ZNArray_h
