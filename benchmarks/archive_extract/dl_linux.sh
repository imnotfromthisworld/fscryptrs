#!/usr/bin/bash
# taken from https://github.com/rfjakob/gocryptfs/blob/master/tests/dl-linux-tarball.bash
#
# This script checks the size of /tmp/linux-6.0.tar.gz and downloads
# a fresh copy if the size is incorrect or the file is missing.

URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.0.tar.gz
TGZ=/tmp/linux-6.0.tar.gz

SIZE_WANT=214052479
SIZE_ACTUAL=0
if [[ -e $TGZ ]]; then
    if [[ $OSTYPE == linux* ]]; then
        SIZE_ACTUAL=$(stat -c %s "$TGZ")
    else
        # Mac OS X
        SIZE_ACTUAL=$(stat -f %z "$TGZ")
    fi
fi

if [[ $SIZE_ACTUAL -ne $SIZE_WANT ]]; then
    echo "Downloading linux-6.0.tar.gz"
    if command -v wget >/dev/null; then
        wget -nv -c -O "$TGZ" "$URL"
    else
        curl -o "$TGZ" "$URL"
    fi
fi
