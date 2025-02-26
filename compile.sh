#!/bin/bash


clang ./src/main.c -lpcap -Wall -Wextra -o ./main

if [ $? -eq 0 ];then
    sudo ./main
else
    echo "compile goes wrong"
fi
