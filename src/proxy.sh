#!/bin/bash

userID="${1:-user1@email.com}"
password="${2:-password1}"

host="${3:-localhost}"
tcp_port="${4:-3333}"

movie="${5:-cars.dat}"

server_port="${6:-10000}"
player_port="${7:-9000}"

echo "Starting proxy passthrough from $host:$server_port to $host:$player_port"

# ./compile.sh 
java -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService.hjUDPproxy.hjUDPproxy $userID $password $host $tcp_port $movie $server_port $player_port
