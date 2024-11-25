#!/bin/bash

userID="${1:-user1@email.com}"
password="${2:-password1}"

host="${3:-localhost}"
tcp_port="${4:-3333}"

movie="${5:-monsters.dat}"

server_endpoint="${6:-localhost:10000}"
player_endpoint="${7:-localhost:9000}"

echo "Starting proxy passthrough from $server_endpoint to $player_endpoint"

./compile.sh 
java -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService.hjUDPproxy.hjUDPproxy $userID $password $host $tcp_port $movie $server_endpoint $player_endpoint
