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



Vector *vectorInit(uint64_t size, VectorType type){
    // Adding 20 here just to add an extra space just in Case
    Vector *newVect =  (Vector *)malloc(sizeof(Vector)+ (size + 20));


}











