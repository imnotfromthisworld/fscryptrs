#!/usr/bin/bash

cd "$(dirname "$0")" || exit

T=$(mktemp -d)

# Download /tmp/linux-6.0.tar.gz
./dl_linux.sh

cmd="tar xzf /tmp/linux-6.0.tar.gz -C '$T/mnt' && sync"

cd "$(dirname "$0")" || exit
hyperfine --warmup 5 --runs 100 --export-json "results.json" "$@" \
    -n "cha_bla_blk"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest blake2 --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "cha_bla_str"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest blake2 --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "cha_sha_blk"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest sha3   --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "cha_sha_str"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest sha3   --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "cha_non_blk"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest none   --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "cha_non_str"   --prepare "./prepare.sh '$T' --cipher cha-cha20-poly1305 --digest none   --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_bla_blk"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest blake2 --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_bla_str"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest blake2 --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_sha_blk"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest sha3   --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_sha_str"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest sha3   --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_non_blk"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest none   --mode block  " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "aes_non_str"   --prepare "./prepare.sh '$T' --cipher aes256-gcm         --digest none   --mode stream " --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "default"       --prepare "mkdir -p '$T/mnt'         "                                                   --conclude "rm -rf '$T/mnt'" "$cmd" \
    -n "gocryptfs_aes" --prepare "./other/prepare_gocryptfs.sh '$T'        "                                    --conclude "./cleanup.sh '$T'" "$cmd" \
    -n "gocryptfs_cha" --prepare "./other/prepare_gocryptfs.sh '$T' -xchacha"                                   --conclude "./cleanup.sh '$T'" "$cmd"
    # -n "encfs"         --prepare "./other/prepare_encfs.sh '$T'"                                                --conclude "./cleanup.sh '$T'" "$cmd" 
    # encfs is very slow, not worth it to compare, uncomment if really want to

rm -rf "$T"
