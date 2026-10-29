#!/bin/sh
# flash.sh PORT [cargo features]: builds, then flashes (never erasing) with the bootloader ESP-IDF built.
set -eu
port=$1; features=${2:-}
cargo build --release ${features:+--features $features}
elf=target/xtensa-esp32s3-espidf/release/esp-idf-svc-alpn
bl=$(ls -t target/xtensa-esp32s3-espidf/release/build/esp-idf-sys-*/out/build/bootloader/bootloader.bin | head -1)
espflash flash --non-interactive -p "$port" --flash-size 8mb --flash-freq 80mhz --bootloader "$bl" \
    --partition-table partitions.csv "$elf"
