#!/bin/bash

sender_host="${1:-localhost}"
sender_port="${2:-10000}"

receiver_host="${1:-localhost}"
receiver_port="${2:-9000}"

echo "Starting proxy passthrough from $sender_host:$sender_port to $receiver_host:$receiver_port"

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService.hjUDPproxy.hjUDPproxy $sender_host:$sender_port $receiver_host:$receiver_port
