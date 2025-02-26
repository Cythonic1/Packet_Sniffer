#include <stdint.h>



// This gonna be custome vector to make it easy handle with dynamic allocation stuff

typedef struct Vector {
    unsigned char *value;
    uint64_t size;
    uint64_t capacity;
}Vector;
