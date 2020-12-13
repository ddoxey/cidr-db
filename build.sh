#!/bin/bash

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/src"

rm bin/* 2>/dev/null
rm lib/* 2>/dev/null
rm -rf CMakeCache.txt CMakeFiles

cd ../build && cmake ../src/

if [[ "$1" == "-c" ]]
then
    make clean
fi

make
