#!/bin/bash
#
# Use this script to build cidr-db on a Ubuntu system.
#
# ./build.sh     # build
#
# ./build.sh -p  # make clean & purge cmake artfacts
#
CMAKE="$(which cmake)"
MAKE="$(which make)"

function build()
{
    cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    mkdir -p build
    cd build

    $CMAKE ../src/ || return 1

    if [[ "$1" == "-p" ]]
    then
        $MAKE clean || return 1

        rm bin/* 2>/dev/null
        rm lib/* 2>/dev/null
        rm -rf Makefile CMakeCache.txt CMakeFiles cmake_install.cmake
    
        echo "-- Build files have been purged from: $(pwd)"

        return 0
    fi

    $MAKE || return 1
}

function main()
{
    if [[ -z $MAKE ]]
    then
        echo "make is not installed" >&2 && return 1
    fi

    if [[ -z $CMAKE ]]
    then
        echo "cmake not installed" >&2 && return 1
    fi

    if ! apt list --installed 2>/dev/null | grep -q 'libboost1[.]67[-]'
    then
        echo "libboost1.67 not installed" >&2 && return 1
    fi

    build "$@"
}

if [[ $(caller | awk '{print $1}') -eq 0 ]]; then main "$@"; fi
