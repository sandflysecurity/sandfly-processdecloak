#!/bin/bash
# Build script for sandfly-processdecloak
#
# sandfly-processdecloak is a utility to decloak hidden processes on Linux from loadable kernel module stealth rootkits.
#
# MIT Licensed (c) 2020 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for Linux/386"
env GOOS=linux GOARCH=386 go build -o sandfly-processdecloak.386 -ldflags="-s -w" sandfly-processdecloak
