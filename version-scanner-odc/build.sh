#!/bin/bash

# This script builds the Docker/Podman image for a specified platform.

# Determine the container CLI to use (defaults to docker)
: "${CONTAINER_CLI:=docker}"
echo "Using container CLI: $CONTAINER_CLI"

# Check for the platform argument
if [ -z "$1" ]; then
    echo "Usage: $0 <platform>"
    echo "Available platforms: osx, linux"
    exit 1
fi

PLATFORM=$1

# Check if odc-data directory exists
if [ ! -d "odc-data" ]; then
    echo "❌ Error: 'odc-data' directory not found."
    echo ""
    echo "Please run the following script to create and initialize the data directory:"
    echo "  ./get-odc-data.sh"
    echo ""
    exit 1
fi

case "$PLATFORM" in
    "osx")
        echo "Building for OS X (linux/arm64)..."
        $CONTAINER_CLI build --platform linux/arm64 -f Dockerfile-odc -t version-scanner:odc-arm64 .
        ;;
    "linux")
        echo "Building for Linux (linux/amd64)..."
        $CONTAINER_CLI build --platform=linux/amd64 -f Dockerfile-odc -t version-scanner:odc-amd64 .
        ;;
    *)
        echo "Error: Invalid platform '$PLATFORM'."
        echo "Available platforms: osx, linux"
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    echo "Build successful for platform: $PLATFORM"
else
    echo "Build failed for platform: $PLATFORM"
fi
