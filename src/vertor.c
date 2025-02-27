#include "./vector.h"
#include <stdio.h>


// This gonna be custome vector to make it easy handle with dynamic allocation stuff


Vector *vectorInit(){
    // Adding 20 here just to add an extra space just in Case
    Vector *newVect =  (Vector *)malloc(sizeof(Vector));
    if(newVect == NULL){
        return NULL;
    }
    newVect->header.size = 0;
    newVect->header.capacity = 2;
    newVect->value = calloc(newVect->header.capacity,sizeof(void *) );
    if(newVect->value == NULL){
        perror("Error while allocating values\n");
        free(newVect);
        return NULL;
    }
    return newVect;
}


Status vectorAppend(Vector *vector, void *data){
    if(vector->header.capacity <= vector->header.size){
        vectorExpend(vector);
    }
    vector->value[vector->header.size] = data;
    vector->header.size += 1;
    return Ok;
}

Status vectorExpend(Vector *vector){
    printf("New resize has been occur\n");
    vector->header.capacity = vector->header.capacity + 10;
    printf("size %ld\n", vector->header.capacity);
    void **tmp = realloc(vector->value, vector->header.capacity * sizeof(void *));
    if(tmp == NULL){
        return Err;
    }
    vector->value = tmp;
    return Ok;
}










