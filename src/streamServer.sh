#!/bin/bash

echo "Starting streamServer"

# ./compile.sh 
java -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService.hjStreamServer.hjStreamServer
