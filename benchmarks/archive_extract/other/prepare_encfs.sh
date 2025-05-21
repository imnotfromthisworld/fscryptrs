#!/usr/bin/bash

T="$1"
echo "creating $T/enc_root and $T/mnt"
mkdir -p "$T/enc_root" "$T/mnt"

echo "initializing  filesystem"
cp "./other/encfs.xml" "$T/enc_root/.encfs6.xml"
encfs --extpass "echo testing123" --verbose "$T/enc_root" "$T/mnt"

sleep 1

sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
