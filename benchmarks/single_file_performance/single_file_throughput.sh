#!/bin/bash

# Configuration
TEST_FILE="/tmp/tmp.xAkS34TnZ0/test_file" # IMPORTANT: Set this to your desired test path
BLOCK_SIZE="1G"                           # Block size for dd (e.g., 1M, 4K, 64K)
FILE_COUNT=1                              # Number of blocks, 1024 * 1M = 1GB
NUM_RUNS=100                              # How many times to run the test

# --- Functions ---

# Function to clean up the test file
cleanup() {
    if [ -f "$TEST_FILE" ]; then
        rm -f "$TEST_FILE"
    fi
}

# Trap for cleaning up on script exit or interruption
trap cleanup EXIT INT TERM

# Function to clear OS caches (requires root/sudo)
clear_caches() {
    sudo sync
    sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
}

# Function to calculate average
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

# --- Main Script ---

echo "--- Filesystem I/O Benchmark ---"
echo "Testing path: $(dirname "$TEST_FILE")"
echo "File size per run: $((FILE_COUNT)) * $BLOCK_SIZE = $((FILE_COUNT * ${BLOCK_SIZE//[^0-9]/})) bytes"
echo "Number of runs: $NUM_RUNS"
echo ""

# Arrays to store speeds
declare -a write_speeds
declare -a read_speeds

# --- Write Test ---
echo "Starting Write Benchmark..."
for i in $(seq 1 $NUM_RUNS); do
    echo -n "  Run $i of $NUM_RUNS..."
    # Ensure no old test file exists for a fresh write
    cleanup

    # Run dd for write, redirect stderr (where dd prints its info)
    # to a variable, then extract the speed.
    OUTPUT=$(dd if=/dev/zero of="$TEST_FILE" bs="$BLOCK_SIZE" count="$FILE_COUNT" conv=fdatasync 2>&1)

    # Extract speed using grep and awk
    # The output format for dd is typically: "X bytes (Y GB) copied, Z s, W MB/s"
    SPEED=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $1}')
    UNIT=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $2}' | sed 's#/s##')

    # Convert to MB/s if in GB/s or KB/s for consistent calculation
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

# --- Read Test ---
echo "Starting Read Benchmark..."
for i in $(seq 1 $NUM_RUNS); do
    echo -n "  Run $i of $NUM_RUNS..."

    # Clear caches before each read test for more accurate raw disk read speed
    clear_caches

    # Run dd for read
    OUTPUT=$(dd if="$TEST_FILE" of=/dev/null bs="$BLOCK_SIZE" count="$FILE_COUNT" 2>&1)

    # Extract speed
    SPEED=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $1}')
    UNIT=$(echo "$OUTPUT" | grep -oE '[0-9\.]+\s(MB|GB|KB)/s' | awk '{print $2}' | sed 's#/s##')

    # Convert to MB/s if in GB/s or KB/s
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

# --- Results ---
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

# Cleanup at the end
cleanup
