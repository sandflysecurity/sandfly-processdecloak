#!/bin/bash
# Build script for sandfly-processdecloak
#
# sandfly-processdecloak is a utility to decloak hidden processes on Linux from loadable kernel module stealth rootkits.
#
# MIT Licensed (c) 2020 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for Linux/amd64"
env GOOS=linux GOARCH=amd64 go build -o sandfly-processdecloak -ldflags="-s -w" sandfly-processdecloak
