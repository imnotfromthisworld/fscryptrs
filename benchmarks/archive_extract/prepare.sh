#!/usr/bin/bash

T="$1"
echo "creating $T/enc_root and $T/mnt"
mkdir -p "$T/enc_root" "$T/mnt"

echo "initializing  filesystem"
fscryptrs init --password "testing123" "${@:2}" "$T/enc_root"
fscryptrs mount --password "testing123" "$T/enc_root" "$T/mnt" &
disown

sleep 1
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
