#!/bin/bash

group="${1:-224.20.20.20}"
port="${2:-2000}"

echo "Listening for Multicast on $group:$port"

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar TestMulticast.MulticastReceiver $group $port
