#!/bin/bash
# Build script for sandfly-processdecloak
#
# sandfly-processdecloak is a utility to decloak hidden processes on Linux from loadable kernel module stealth rootkits.
#
# Sandfly produces an agentless Linux endpoint detection and incident response platform (EDR). Sandfly hunts for threats
# against your Linux systems without loading any agents on your endpoints and works against most distributions and architectures
#
# Please see our website for more information or a free trial. 
#
# MIT Licensed (c) 2020-2022 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for Linux/386"
env GOOS=linux GOARCH=386 go build -o sandfly-processdecloak.386 -ldflags="-s -w"