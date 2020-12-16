#!/bin/bash
#
# This script demonstrates the REST service in action.
#
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REST="build/bin/cidrdb_rest"
CIDR_LIST="data/sample-cidrs.list"
CIDR_DB="$(sed 's/[.]list/.db/' <<< "$CIDR_LIST")"


function stop_rest_service()
{
    local pid=$(pidof $REST)
    if [[ -n $pid ]]; then kill $pid; fi
}

function restart_rest_service()
{
    stop_rest_service
    $REST 127.0.0.1 8080 $CIDR_DB >/dev/null 2>&1 &
}

function rest()
{
    local method="$1"
    local path="$2"
    local payload="$3"

    if [[ -n $payload ]]; then payload="-d $payload"; fi

    curl -s                              \
         -X $method                      \
         -H 'Accept: application/json'   \
         "http://127.0.0.1:8080${path}"  \
         $payload
}

function run()
{
    for file in $REST $CIDR_LIST
    do
        if [[ ! -f $file ]]
        then
            echo "No such file: $file" >&2 && exit 1
        fi
    done

    >$CIDR_DB

    restart_rest_service

    for cidr in $(cat $CIDR_LIST)
    do
        if [[ ! $(rest GET "/$cidr") =~ '"present":false' ]]
        then
            echo "$cidr is supposed to be absent!" >&2
            continue
        fi

        if [[ ! $(rest PUT "/$cidr") =~ '"present":true' ]]
        then
            echo "Failed to add $cidr to CIDR-DB!" >&2
            continue
        fi

        printf "  %15s added to CIDR-DB\n" $cidr
    done

    for cidr in $(cat $CIDR_LIST)
    do
        ip="$(sed 's|[.]0/[0-9]\+|.10|' <<< "$cidr")"

        if [[ $(rest GET "/$ip") =~ "\"${cidr}\"" ]]
        then
            echo -en "\e[32;1mOK\e[0m "
        else
            echo -en "\e[31;1mFAIL\e[0m "
        fi

        printf "%14s \u2208 %15s\n" $ip $cidr
    done

    for cidr in $(cat $CIDR_LIST)
    do
        if [[ ! $(rest DELETE "/$cidr") =~ '"present":false' ]]
        then
            echo "$cidr is supposed to be absent!" >&2
            continue
        fi

        printf "  %15s deleted from CIDR-DB\n" $cidr
    done

    for cidr in $(cat $CIDR_LIST)
    do
        ip="$(sed 's|[.]0/[0-9]\+|.10|' <<< "$cidr")"

        if [[ $(rest GET "/$ip") =~ "\"${cidr}\"" ]]
        then
            echo -en "\e[31;1mFAIL\e[0m "
        else
            echo -en "\e[32;1mOK\e[0m "
        fi

        printf "%14s \u2209 %15s\n" $ip $cidr
    done

    stop_rest_service
}


if [[ $(caller | awk '{print $1}') -eq 0 ]]; then run "$@"; fi
