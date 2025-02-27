#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



// This gonna be custome vector to make it easy handle with dynamic allocation stuff

typedef enum VectorType{
    INT,
    string,
    INT16,
    INT32,
    INT8, 
}VectorType;

typedef struct VectorHeaders {
    uint64_t size;
    uint64_t capacity;
    VectorType vectorType;
}VectorHeaders;

typedef struct Vector {
    VectorHeaders header;
    void **value;
}Vector;


Vector *vectorInit(VectorType type);
void vectorAppend(Vector *vector, void *data);
void vectorExpend(Vector *vector);

Vector *vectorInit(VectorType type){
    // Adding 20 here just to add an extra space just in Case
    Vector *newVect =  (Vector *)malloc(sizeof(Vector));
    newVect->header.size = 0;
    newVect->header.capacity = 20;
    *newVect->value = malloc(sizeof(void *) * newVect->header.capacity);
    return newVect;
}


void vectorAppend(Vector *vector, void *data){
    if(vector->header.capacity <= vector->header.size){
        vectorExpend(vector);
    }

    vector->value[vector->header.size] = data;
    vector->header.size += 1;
}











