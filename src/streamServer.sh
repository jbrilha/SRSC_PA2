#!/bin/bash

host="${1:-localhost}"
port="${2:-10000}"
file="${3:-StreamingService/hjStreamServer/movies/cars.dat}"
filename=$(basename "$file")

echo "Starting streamServer on $host:$port for file \"$filename\""

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService.hjStreamServer.hjStreamServer $file $host $port
