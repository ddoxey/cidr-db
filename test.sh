#!/bin/bash
#
# This script demonstrates the CLI in action.
#
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLI="build/bin/cidrdb_cli"
CIDR_LIST="data/sample-cidrs.list"
CIDR_DB="$(sed 's/[.]list/.db/' <<< "$CIDR_LIST")"

for file in $CLI $CIDR_LIST
do
    if [[ ! -f $file ]]
    then
        echo "No such file: $file" >&2 && exit 1
    fi
done

rm -f $CIDR_DB 2>/dev/null

for cidr in $(cat $CIDR_LIST)
do
    ip="$(sed 's|[.]0/[0-9]\+|.10|' <<< "$cidr")"

    if [[ "$1" == "-v" ]]
    then
        echo -e "\n$CLI --in $CIDR_LIST --db $CIDR_DB --ip $ip"
    fi

    got=$($CLI --in $CIDR_LIST --db $CIDR_DB --ip "$ip")

    if [[ "$got" == "$cidr" ]]
    then
        echo -en "\e[32;1m  OK\e[0m : "
    else
        echo -en "\e[31;1mFAIL\e[0m : "
    fi

    printf "%13s -> %15s <=> %13s\n" $ip $got $cidr
done

