#!/bin/sh
# drive.sh PORT NAME: monitors the board into logs/NAME-device.log while openssl connects to it.
set -u
port=$1 name=$2
elf=target/xtensa-esp32s3-espidf/release/esp-idf-svc-alpn
timeout 40 espflash monitor --non-interactive -p "$port" --elf "$elf" > logs/$name-device.log 2>&1 &
sleep 15
ip=$(grep -a -o 'connect [0-9.]*:443' logs/$name-device.log | head -1 | cut -d' ' -f2 | cut -d: -f1)
echo "ip=$ip"
echo | timeout 15 openssl s_client -alpn h2 -connect $ip:443 > logs/$name-openssl.txt 2>&1
echo "openssl exit $?"
wait
