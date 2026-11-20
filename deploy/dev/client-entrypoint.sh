#!/bin/sh
set -eu

for name in controlplane edge; do
    ip=$(getent hosts "$name" | awk '{print $1; exit}')
    if [ -n "$ip" ] && ! grep -q " $name\$" /etc/hosts; then
        echo "$ip $name" >> /etc/hosts
    fi
done

exec /usr/local/bin/opensase-client "$@"
