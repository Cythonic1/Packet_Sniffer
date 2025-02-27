#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum VectorType{
    INT,
    string,
    INT16,
    INT32,
    INT8, 
}VectorType;


typedef enum Status {Ok, Err} Status;

typedef struct VectorHeaders {
    uint64_t size;
    uint64_t capacity;
    VectorType vectorType;
}VectorHeaders;

typedef struct Vector {
    VectorHeaders header;
    void **value;
}Vector;


Vector *vectorInit();
Status vectorAppend(Vector *vector, void *data);
Status vectorExpend(Vector *vector);
