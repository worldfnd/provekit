#!/bin/sh
if [ ! -e "./verifier-server" ]; then
    echo "Error: verifier-server binary not found!" >&2
    ls -la
    exit 1
fi

if [ ! -x "./verifier-server" ]; then
    echo "Warning: verifier-server was not executable, making it executable..." >&2
    ls -la
    chmod u+x ./verifier-server
fi

echo "Binary details:"
ls -la ./verifier-server
echo "Starting server..."

exec ./verifier-server
