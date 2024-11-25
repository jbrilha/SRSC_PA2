#!/bin/bash

group="${1:-224.20.20.20}"
port="${2:-2000}"
interval="${3:-1}"

echo "Starting Multicast on $group:$port with interval $interval"

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar TestMulticast.MulticastSender $group $port $interval
