#!/bin/bash

userID="${1:-user1@email.com}"
password="${2:-password1}"

host="${3:-localhost}"
tcp_port="${4:-3333}"

type="${5:-R}"
filename="${6:-server2.pdf}"

mode="${7:-octet}"

find . -name '*.class' -delete
javac -cp .:../libs/bcprov-jdk18on-1.78.1.jar *.java

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar TFTPClient $userID $password $host $tcp_port $type $filename $mode
