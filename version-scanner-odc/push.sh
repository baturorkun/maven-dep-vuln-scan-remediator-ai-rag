#!/bin/bash

# This script logs in to a container registry, tags a local image, and pushes it.

# Determine the container CLI to use (defaults to docker)
: "${CONTAINER_CLI:=docker}"
echo "Using container CLI: $CONTAINER_CLI"

# Check for required arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <docker_hub_username> <platform>"
    echo "Pushes the specified platform's image to Docker Hub."
    echo ""
    echo "Arguments:"
    echo "  <docker_hub_username>   Your username on Docker Hub."
    echo "  <platform>              The platform of the image to push. Available: osx, linux."
    exit 1
fi

DOCKER_HUB_USERNAME=$1
PLATFORM=$2
IMAGE_NAME="version-scanner"
LOCAL_TAG=""

# Determine the local tag based on the platform from build.sh
case "$PLATFORM" in
    "osx")
        LOCAL_TAG="odc-arm64"
        ;;
    "linux")
        LOCAL_TAG="odc-amd64"
        ;;
    *)
        echo "Error: Invalid platform '$PLATFORM'."
        echo "Available platforms: osx, linux"
        exit 1
        ;;
esac

SOURCE_IMAGE="$IMAGE_NAME:$LOCAL_TAG"
TARGET_IMAGE="$DOCKER_HUB_USERNAME/$IMAGE_NAME:$LOCAL_TAG"

echo "--------------------------------------------------"
echo "Target Image: $TARGET_IMAGE"
echo "--------------------------------------------------"

# Step 1: Log in to Docker Hub
echo ""
echo "Step 1: Logging in to Docker Hub as '$DOCKER_HUB_USERNAME'..."
$CONTAINER_CLI login -u "$DOCKER_HUB_USERNAME" docker.io
if [ $? -ne 0 ]; then
    echo "❌ Error: $CONTAINER_CLI login failed. Please check your credentials."
    exit 1
fi
echo "Login successful."

# Step 2: Tag the image for Docker Hub
echo ""
echo "Step 2: Tagging local image '$SOURCE_IMAGE' for Docker Hub..."
$CONTAINER_CLI tag "$SOURCE_IMAGE" "$TARGET_IMAGE"
if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to tag image."
    echo "Please ensure the source image '$SOURCE_IMAGE' exists. You can build it with './build.sh $PLATFORM'."
    exit 1
fi
echo "Tagging successful."

# Step 3: Push the image to Docker Hub
echo ""
echo "Step 3: Pushing image '$TARGET_IMAGE' to Docker Hub..."
$CONTAINER_CLI push "$TARGET_IMAGE"
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully pushed image '$TARGET_IMAGE' to Docker Hub."
else
    echo ""
    echo "❌ Error: Failed to push image. Please check your repository permissions."
    exit 1
fi
