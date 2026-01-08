#!/usr/bin/bash

echo "Empty"
./empty_syscall.user
sleep 1
echo "Read"
./read_syscall.user
sleep 1
echo "Open"
./open_syscall.user
sleep 1
echo "Getcwd"
./getcwd_syscall.user
