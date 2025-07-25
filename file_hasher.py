# file_hasher.py

import hashlib
import os

def calculate_file_hash(filepath, algorithm="sha256", block_size=65536):
    """
    Calculates the hash of a file using a specified algorithm.
    Reads the file in chunks to handle large files efficiently.
    """
    if not os.path.exists(filepath):
        return None, f"Error: File not found at '{filepath}'"
    
    # Choose hashing algorithm
    if algorithm.lower() == "md5":
        hasher = hashlib.md5()
    elif algorithm.lower() == "sha1":
        hasher = hashlib.sha1()
    elif algorithm.lower() == "sha256":
        hasher = hashlib.sha256()
    elif algorithm.lower() == "sha512":
        hasher = hashlib.sha512()
    else:
        return None, f"Error: Unsupported algorithm '{algorithm}'. Choose from md5, sha1, sha256, sha512."

    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest(), None
    except Exception as e:
        return None, f"Error calculating hash: {e}"

if __name__ == "__main__":
    print("\n--- Simple File Hashing Utility ---")
    print("Enter 'q' to quit.")

    while True:
        file_path = input("\nEnter the path to the file you want to hash: ")
        if file_path.lower() == 'q':
            print("Exiting File Hasher. Goodbye!")
            break

        if not file_path:
            print("File path cannot be empty. Please try again.")
            continue
            
        if not os.path.exists(file_path):
            print(f"Error: File not found at '{file_path}'. Please check the path.")
            continue

        # Ask for algorithm choice
        algo_choice = input("Choose hashing algorithm (md5, sha1, sha256, sha512 - default: sha256): ").lower()
        if algo_choice not in ["md5", "sha1", "sha256", "sha512"]:
            algo_choice = "sha256"
        
        file_hash, error_message = calculate_file_hash(file_path, algorithm=algo_choice)

        if file_hash:
            print(f"\nFile: {file_path}")
            print(f"Algorithm: {algo_choice.upper()}")
            print(f"Hash: {file_hash}")
        else:
            print(f"\n{error_message}")
        print("---------------------------------------")