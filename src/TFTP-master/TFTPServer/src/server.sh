#!/bin/bash

tcp_port="${1:-3333}"

find . -name '*.class' -delete
javac -cp .:../libs/bcprov-jdk18on-1.78.1.jar *.java
java -cp .:../libs/bcprov-jdk18on-1.78.1.jar TFTPServer $tcp_port
