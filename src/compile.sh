#!/bin/bash

javac -cp .:../libs/bcprov-jdk18on-1.78.1.jar **/*.java
javac -cp .:../libs/bcprov-jdk18on-1.78.1.jar StreamingService/**/*.java
