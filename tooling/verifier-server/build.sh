#!/bin/bash

# Build script for ProveKit Verifier Server
# This script builds the Docker image for the verifier server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building ProveKit Verifier Server Docker Image${NC}"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}Error: Dockerfile not found. Please run this script from the tooling/verifier-server directory.${NC}"
    exit 1
fi

# Get the project root (two levels up)
PROJECT_ROOT="$(cd ../.. && pwd)"
echo -e "${YELLOW}Project root: ${PROJECT_ROOT}${NC}"

# Build the Docker image
echo -e "${BLUE}Building Docker image...${NC}"
docker build \
    --tag provekit-verifier-server:latest \
    --tag provekit-verifier-server:$(date +%Y%m%d-%H%M%S) \
    --build-arg TARGETOS=linux \
    --build-arg TARGETARCH=amd64 \
    --file Dockerfile \
    "${PROJECT_ROOT}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Docker image built successfully!${NC}"
    echo -e "${GREEN}Image tags:${NC}"
    echo -e "  - provekit-verifier-server:latest"
    echo -e "  - provekit-verifier-server:$(date +%Y%m%d-%H%M%S)"
    echo ""
    echo -e "${BLUE}To run the container:${NC}"
    echo -e "  docker run -p 3000:3000 provekit-verifier-server:latest"
    echo ""
    echo -e "${BLUE}Or use docker-compose:${NC}"
    echo -e "  docker-compose up"
else
    echo -e "${RED}❌ Docker build failed!${NC}"
    exit 1
fi
