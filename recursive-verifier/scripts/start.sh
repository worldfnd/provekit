#!/bin/sh
if [ ! -f "./verifier-server" ]; then
    echo "Error: verifier-server binary not found!"
    ls -la
    exit 1
fi

if [ ! -x "./verifier-server" ]; then
    echo "Warning: verifier-server was not executable, making it executable..."
    ls -la
    chmod +x ./verifier-server
fi

echo "Binary details:"
ls -la ./verifier-server
echo "Starting server..."

exec ./verifier-server