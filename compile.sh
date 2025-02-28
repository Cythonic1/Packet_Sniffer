#!/bin/bash


clang ./src/main.c -lpcap -Wall -Wextra -fsanitize=address -fsanitize=undefined -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -z relro -z now -o ./main

if [ $? -eq 0 ];then
    sudo ./main
else
    echo "compile goes wrong"
fi
