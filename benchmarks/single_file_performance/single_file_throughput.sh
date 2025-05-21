#!/bin/bash

cd "$(dirname "$0")" || exit

T=$(mktemp -d)

# Config
TEST_FILE="$T/test_file"
BLOCK_SIZE="1G"
FILE_COUNT=1
NUM_RUNS=100

cleanup() {
    if [ -f "$TEST_FILE" ]; then
        rm -f "$TEST_FILE"
    fi
}

trap cleanup EXIT INT TERM

clear_caches() {
    sudo sync
    sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
}

calculate_average() {
    local -n speeds_array=$1 # Bash 4.3+ for nameref
    local sum=0
    local count=0

    for speed in "${speeds_array[@]}"; do
        sum=$(echo "$sum + $speed" | bc -l)
        count=$((count + 1))
    done

    if [ "$count" -gt 0 ]; then
        local average
        average=$(echo "scale=2; $sum / $count" | bc -l)
        echo "$average"
    else
        echo "0.00"
    fi
}

echo "--- Filesystem I/O Benchmark ---"
echo "Testing path: $(dirname "$TEST_FILE")"
echo "File size per run: $((FILE_COUNT)) * $BLOCK_SIZE = $((FILE_COUNT * ${BLOCK_SIZE//[^0-9]/})) bytes"
echo "Number of runs: $NUM_RUNS"
echo ""

declare -a write_speeds
declare -a read_speeds

echo "Starting Write Benchmark..."
for i in $(seq 1 $NUM_RUNS); do
    echo -n "  Run $i of $NUM_RUNS..."
    cleanup

    OUTPUT=$(dd if=/dev/zero of="$TEST_FILE" bs="$BLOCK_SIZE" count="$FILE_COUNT" conv=fdatasync 2>&1)

    SPEED=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $1}')
    UNIT=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $2}' | sed 's#/s##')

    if [[ "$UNIT" == "GB" ]]; then
        SPEED=$(echo "scale=2; $SPEED * 1024" | bc -l)
    elif [[ "$UNIT" == "KB" ]]; then
        SPEED=$(echo "scale=2; $SPEED / 1024" | bc -l)
    fi

    if [ -n "$SPEED" ]; then
        echo "    Write Speed: $SPEED MB/s"
        write_speeds+=("$SPEED")
    else
        echo "    Failed to get write speed for run $i."
    fi
done

echo "Starting Read Benchmark..."
for i in $(seq 1 $NUM_RUNS); do
    echo -n "  Run $i of $NUM_RUNS..."

    clear_caches

    OUTPUT=$(dd if="$TEST_FILE" of=/dev/null bs="$BLOCK_SIZE" count="$FILE_COUNT" 2>&1)

    SPEED=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $1}')
    UNIT=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $2}' | sed 's#/s##')

    if [[ "$UNIT" == "GB" ]]; then
        SPEED=$(echo "scale=2; $SPEED * 1024" | bc -l)
    elif [[ "$UNIT" == "KB" ]]; then
        SPEED=$(echo "scale=2; $SPEED / 1024" | bc -l)
    fi

    if [ -n "$SPEED" ]; then
        echo "    Read Speed: $SPEED MB/s"
        read_speeds+=("$SPEED")
    else
        echo "    Failed to get read speed for run $i."
    fi
done

echo "--- Benchmark Results ---"
echo ""
printf -v w_sp '%s,' "${write_speeds[@]}"
echo "Individual Write Speeds (MB/s): [$w_sp]"
AVG_WRITE_SPEED=$(calculate_average write_speeds)
echo "Average Write Speed: $AVG_WRITE_SPEED MB/s"
echo ""

printf -v r_sp '%s,' "${read_speeds[@]}"
echo "Individual Read Speeds (MB/s): [$r_sp]"
AVG_READ_SPEED=$(calculate_average read_speeds)
echo "Average Read Speed: $AVG_READ_SPEED MB/s"

cleanup
