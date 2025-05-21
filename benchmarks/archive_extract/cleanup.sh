#!/usr/bin/bash

T="$1"

echo "unmounting filesystem at $T/mnt"
fusermount -uz "$T/mnt"
echo "removing $T/enc_root"
rm -rf "$T/enc_root"
