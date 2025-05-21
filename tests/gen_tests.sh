cd "$(dirname "$0")" || exit

dd if=/dev/random of=./file_16_kb bs=16K count=1
dd if=/dev/random of=./file_1_gb bs=1G count=1
dd if=/dev/random of=./file_4095_b bs=4095 count=1
dd if=/dev/random of=./file_4097_b bs=4097 count=1
dd if=/dev/random of=./file_4_kb bs=4096 count=1

mkdir ./block ./stream
