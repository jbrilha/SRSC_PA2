#!/bin/bash

host="${1-localhost}"
op="${2:-R}"
file="${3-server1.jpg}"

find . -name '*.class' -delete
javac -cp .:../libs/bcprov-jdk18on-1.78.1.jar *.java

java -cp .:../libs/bcprov-jdk18on-1.78.1.jar TFTPClient $host $op $file
