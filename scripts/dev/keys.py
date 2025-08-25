from google.cloud import storage
from google.oauth2 import service_account
import os
import requests

def list_bucket_contents(bucket_name, service_account_path):
    
    credentials = service_account.Credentials.from_service_account_file(
        service_account_path
    )
    
    storage_client = storage.Client(credentials=credentials)
    
    bucket = storage_client.bucket(bucket_name)
    
    blobs = bucket.list_blobs()
    
    print(f"Contents of bucket: {bucket_name}")
    print("=" * 50)
    
    file_count = 0
    total_size = 0
    
    for blob in blobs:
        file_count += 1
        size_mb = blob.size / (1024 * 1024)
        
        print(f"File: {blob.name}")
        print(f"  Size: {size_mb:.2f} MB")
        print(f"  Created: {blob.time_created}")
        print(f"  Updated: {blob.updated}")
        print(f"  Storage Class: {blob.storage_class}")
        print(f"  Public URL: {blob.public_url}")
        print("-" * 30)
        
        total_size += blob.size
    
    total_size_mb = total_size / (1024 * 1024)
    print(f"\nSummary:")
    print(f"Total files: {file_count}")
    print(f"Total size: {total_size_mb:.2f} MB")

def upload_file(bucket_name, service_account_path, local_file_path, destination_blob_name=None):
    
    credentials = service_account.Credentials.from_service_account_file(
        service_account_path
    )
    
    storage_client = storage.Client(credentials=credentials)
    
    bucket = storage_client.bucket(bucket_name)
    
    if destination_blob_name is None:
        destination_blob_name = os.path.basename(local_file_path)
    
    blob = bucket.blob(destination_blob_name)
    
    if not os.path.exists(local_file_path):
        raise FileNotFoundError(f"Local file not found: {local_file_path}")
    
    file_size = os.path.getsize(local_file_path)
    file_size_mb = file_size / (1024 * 1024)
    
    print(f"Uploading {local_file_path} to gs://{bucket_name}/{destination_blob_name}")
    print(f"File size: {file_size_mb:.2f} MB")
    
    blob.upload_from_filename(local_file_path)
    
    print(f"✅ Upload successful!")
    print(f"   Destination: gs://{bucket_name}/{destination_blob_name}")
    print(f"   Size: {file_size_mb:.2f} MB")
    
    return blob

def download_file(bucket_name, service_account_path, blob_name, local_file_path=None):
    
    credentials = service_account.Credentials.from_service_account_file(
        service_account_path
    )
    
    storage_client = storage.Client(credentials=credentials)
    
    bucket = storage_client.bucket(bucket_name)
    
    blob = bucket.blob(blob_name)
    
    if not blob.exists():
        raise FileNotFoundError(f"Blob not found in bucket: {blob_name}")
    
    if local_file_path is None:
        local_file_path = os.path.basename(blob_name)
    
    os.makedirs(os.path.dirname(local_file_path) if os.path.dirname(local_file_path) else '.', exist_ok=True)
    
    blob.reload()
    blob_size_mb = blob.size / (1024 * 1024)
    
    print(f"Downloading gs://{bucket_name}/{blob_name} to {local_file_path}")
    print(f"File size: {blob_size_mb:.2f} MB")
    
    blob.download_to_filename(local_file_path)
    
    if os.path.exists(local_file_path):
        local_size = os.path.getsize(local_file_path)
        local_size_mb = local_size / (1024 * 1024)
        
        print(f"✅ Download successful!")
        print(f"   Source: gs://{bucket_name}/{blob_name}")
        print(f"   Destination: {local_file_path}")
        print(f"   Downloaded size: {local_size_mb:.2f} MB")
        
        if local_size == blob.size:
            print(f"   ✅ File integrity verified")
        else:
            print(f"   ⚠️  File size mismatch: expected {blob_size_mb:.2f} MB, got {local_size_mb:.2f} MB")
    else:
        raise FileNotFoundError(f"Download failed: local file not created")
    
    return local_file_path

def download_public_file(public_url, local_file_path=None):
    
    if local_file_path is None:
        local_file_path = os.path.basename(public_url.split('?')[0])
    
    os.makedirs(os.path.dirname(local_file_path) if os.path.dirname(local_file_path) else '.', exist_ok=True)
    
    print(f"Downloading public file: {public_url}")
    print(f"Local destination: {local_file_path}")
    
    try:
        response = requests.get(public_url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        total_size_mb = total_size / (1024 * 1024)
        
        if total_size > 0:
            print(f"File size: {total_size_mb:.2f} MB")
        
        downloaded_size = 0
        with open(local_file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    
                    if total_size > 0:
                        progress = (downloaded_size / total_size) * 100
                        downloaded_mb = downloaded_size / (1024 * 1024)
                        print(f"\rProgress: {progress:.1f}% ({downloaded_mb:.2f} MB)", end='', flush=True)
        
        print()
        
        if os.path.exists(local_file_path):
            local_size = os.path.getsize(local_file_path)
            local_size_mb = local_size / (1024 * 1024)
            
            print(f"✅ Download successful!")
            print(f"   Source: {public_url}")
            print(f"   Destination: {local_file_path}")
            print(f"   Downloaded size: {local_size_mb:.2f} MB")
            
            if total_size > 0 and local_size == total_size:
                print(f"   ✅ File integrity verified")
            elif total_size > 0:
                print(f"   ⚠️  File size mismatch: expected {total_size_mb:.2f} MB, got {local_size_mb:.2f} MB")
        else:
            raise FileNotFoundError(f"Download failed: local file not created")
        
        return local_file_path
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Download failed: {e}")

def download_public_file_by_name(bucket_name, file_name, local_file_path=None):
    
    public_url = f"https://storage.googleapis.com/{bucket_name}/{file_name}"
    return download_public_file(public_url, local_file_path)

if __name__ == "__main__":
    BUCKET_NAME = "provekit"
    
    SERVICE_ACCOUNT_PATH = "service_account.json"
    
    try:
        print("📋 Current bucket contents:")
        list_bucket_contents(BUCKET_NAME, SERVICE_ACCOUNT_PATH)
        
        print("\n" + "="*60 + "\n")
        
        # download_public_file_by_name(BUCKET_NAME, "basic2_vk.bin", "basic2_vk.bin")
        # upload_file(BUCKET_NAME, SERVICE_ACCOUNT_PATH, "basic2_vk.bin", "basic2_vk.bin")
        
    except Exception as e:
        print(f"Error: {e}")