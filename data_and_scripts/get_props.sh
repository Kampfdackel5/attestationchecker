#!/bin/bash

DNAME=$(adb shell getprop ro.product.model)

if [ -z "$DNAME" ]; then
    DNAME="unknown_device"
fi

TIMESTAMP=$(date +%s)
OUTPUT_FILE="${DNAME}_${TIMESTAMP}_props.txt"

adb shell getprop > "$OUTPUT_FILE"

echo "Props saved to $OUTPUT_FILE"
