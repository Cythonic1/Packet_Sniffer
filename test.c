




#include <stdint.h>
#include <stdio.h>
int main(int argc, char *argv[])
{
    unsigned int number = 0xFFFFFF;
    printf("%d", (number & 0xFFFF00) | (number & 0xFF) );
    
    return 0;
}
