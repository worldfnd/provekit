#!/bin/sh

echo "Checking Python installation..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 not found. Installing..."
    
    apk update
    apk add --no-cache python3 py3-pip
    
    pip3 install requests
    
    echo "Python 3 installed successfully"
else
    echo "Python 3 found: $(python3 --version)"
    
    if ! python3 -c "import requests" 2>/dev/null; then
        echo "Installing requests library..."
        pip3 install requests
    fi
fi

echo "Downloading ZK proof keys..."
python3 keys.py

if [ $? -eq 0 ]; then
    echo "Keys downloaded successfully. Starting verifier server..."
    ./verifier-server
else
    echo "Failed to download keys. Exiting."
    exit 1
fi