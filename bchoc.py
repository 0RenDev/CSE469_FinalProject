import os
import cryptography
import pickle
import argparse
import hashlib
import time
import uuid
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = b"R0chLi4uLi4uLi4="

class Block:
    def __init__(self, previous_hash, case_id, evidence_id, state, creator, owner, data):
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.case_id = self.encrypt(case_id)
        self.evidence_id = self.encrypt(evidence_id)
        self.state = state
        self.creator = creator[:12]
        self.owner = owner[:16]
        self.data = data
        self.data_length = len(data.encode())
        self.block_hash = None

    def encrypt(self, plaintext):
        """Encrypts data using AES-ECB and returns the ciphertext in hexadecimal format."""
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return ciphertext.hex()

    def hash(self):
        """Calculates the SHA-256 hash of the block."""
        block_string = (
            f"{self.previous_hash}{self.timestamp}{self.case_id}{self.evidence_id}"
            f"{self.state}{self.creator}{self.owner}{self.data_length}{self.data}"
        )
        self.block_hash = hashlib.sha256(block_string.encode()).hexdigest()

    def print(self):
        """String representation of the block."""
        return (
            f"Block(\n"
            f"  Previous Hash: {self.previous_hash}\n"
            f"  Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(self.timestamp))}\n"
            f"  Case ID: {self.case_id}\n"
            f"  Evidence ID: {self.evidence_id}\n"
            f"  State: {self.state}\n"
            f"  Creator: {self.creator}\n"
            f"  Owner: {self.owner}\n"
            f"  Data Length: {self.data_length}\n"
            f"  Data: {self.data}\n"
            f"  Block Hash: {self.block_hash}\n"
            f")"
        )

if __name__ == "__main__":
    initial_block = Block(
        previous_hash="0" * 64,  # No parent block for genesis
        case_id=str(uuid.uuid4()),  # Random UUID
        evidence_id="1234",  # Example ID
        state="INITIAL",  # Initial block state
        creator="Admin",  # Block creator
        owner="Police",  # Current owner
        data="Initial evidence data"  # Example metadata
    )
    initial_block.hash()
    print(initial_block.print())