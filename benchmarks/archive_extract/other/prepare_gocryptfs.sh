#!/usr/bin/bash

T="$1"
echo "creating $T/enc_root and $T/mnt"
mkdir -p "$T/enc_root" "$T/mnt"

echo "initializing filesystem"
gocryptfs -init -extpass "echo testing123" "${@:2}" "$T/enc_root"
gocryptfs -extpass "echo testing123" "${@:2}" "$T/enc_root" "$T/mnt"

sleep 1
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
