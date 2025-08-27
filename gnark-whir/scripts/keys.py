#!/usr/bin/env python3

import os
import requests
from pathlib import Path

# Configuration
BUCKET_URL = "https://storage.googleapis.com/provekit"
KEYS_DIR = Path("./keys")

# Keys to download
KEYS = [
    "basic2_vk.bin",
    "basic2_pk.bin", 
    "age_check_vk.bin",
    "age_check_pk.bin",
]

def download_key(filename):
    """Download a single key file."""
    url = f"{BUCKET_URL}/{filename}"
    local_path = KEYS_DIR / filename
    
    print(f"Downloading {filename}...")
    
    try:
        response = requests.get(url, stream=True, timeout=300)
        response.raise_for_status()
        
        # Create directory if needed
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download file
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        # Verify file size
        if local_path.exists() and local_path.stat().st_size > 0:
            size_mb = local_path.stat().st_size / (1024 * 1024)
            print(f"✓ Downloaded {filename} ({size_mb:.2f} MB)")
            return True
        else:
            print(f"✗ Failed: {filename} is empty")
            local_path.unlink(missing_ok=True)
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to download {filename}: {e}")
        local_path.unlink(missing_ok=True)
        return False

def main():
    print("Downloading ZK proof keys...")
    print(f"Bucket: {BUCKET_URL}")
    print(f"Local directory: {KEYS_DIR}")
    print("=" * 50)
    
    # Create keys directory
    KEYS_DIR.mkdir(exist_ok=True)
    
    # Download each key
    success_count = 0
    failed_count = 0
    
    for key in KEYS:
        if download_key(key):
            success_count += 1
        else:
            failed_count += 1
        print()
    
    # Summary
    print("=" * 50)
    print(f"Download complete: {success_count} successful, {failed_count} failed")
    
    if failed_count > 0:
        print("Some downloads failed. Check the errors above.")
        exit(1)
    else:
        print("All keys downloaded successfully!")
        print(f"Keys available in: {KEYS_DIR.absolute()}")

if __name__ == "__main__":
    main()