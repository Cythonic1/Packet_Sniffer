#!/bin/bash


clang ./main.c -lpcap -o main

if [ $? -eq 0 ];then
    sudo ./main
else
    echo "compile goes wrong"
fi
