#!/bin/bash

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cli="build/bin/cidrdb_cli"
cidr_list="data/sample-cidrs.list"
cidr_db="$(sed 's/[.]list/.cdb/' <<< "$cidr_list")"

rm -f $cidr_db 2>/dev/null

for cidr in $(cat $cidr_list)
do
    ip="$(sed 's|[.]0/[0-9]\+|.10|' <<< "$cidr")"

    got=$($cli --in $cidr_list --db $cidr_db --ip "$ip")

    if [[ "$got" == "$cidr" ]]
    then
        echo -en "\e[32;1m  OK\e[0m : "
    else
        echo -en "\e[31;1mFAIL\e[0m : "
    fi

    printf "%13s -> %15s <=> %13s\n" $ip $got $cidr
done

