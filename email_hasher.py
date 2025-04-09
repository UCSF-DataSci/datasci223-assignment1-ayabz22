#!/usr/bin/env python3
"""
Email Hasher Script

This script takes an email address as a command line argument,
hashes it using the SHA-256 algorithm, and writes the hash to a file.

Usage:
    python email_hasher.py <email_address>

Example:
    python email_hasher.py example@email.com
"""

import sys
import hashlib
import argparse

def hash_email(email):
    """
    Hash an email address using SHA-256 and return the hexadecimal digest.
    
    Args:
        email (str): The email address to hash
        
    Returns:
        str: The SHA-256 hash of the email in hexadecimal format
    """
    # 1. Convert the email string to bytes
    byte_email = email.encode()
    # 2. Create a SHA-256 hash object and update it with the email bytes
    hash_256 = hashlib.sha256()
    hash_256.update(byte_email)
    # 3. Return the hash in hexadecimal format
    return hash_256.hexdigest()

def write_hash_to_file(hash_value, filename="hash.email"):
    """
    Write a hash value to a file.
    
    Args:
        hash_value (str): The hash value to write
        filename (str): The name of the file to write to (default: "hash.email")
    """
    # TODO: Implement this function
    # 1. Open the file in write mode
    with open(filename, 'w') as file:
        file.write(hash_value)
    # 2. Write the hash value to the file
    # 3. Close the file

def main():
    """
    Main function to process command line arguments and execute the script.
    """
    
    parser = argparse.ArgumentParser(description="Hash an email and save the hash.")
    parser.add_argument("email", help="The email address to hash")
    args = parser.parse_args()
    hashed_email = hash_email(args.email)
    print(hashed_email)
    write_hash_to_file(hashed_email)

if __name__ == "__main__":
    main()
