import argparse
import sys
import os
import hashlib
import time
import datetime
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import uuid
import ast

blockchain_file_path = os.getenv("BCHOC_FILE_PATH", "blockchain_file.bin")
AES_KEY = b"R0chLi4uLi4uLi4="
INITIAL_STATE = b'INITIAL\0\0\0\0\0'
passwords = {
    "P80P": "BCHOC_PASSWORD_POLICE",
    "L76L": "BCHOC_PASSWORD_LAWYER",
    "A65A": "BCHOC_PASSWORD_ANALYST",
    "E69E": "BCHOC_PASSWORD_EXECUTIVE",
    "C67C": "BCHOC_PASSWORD_CREATOR",
}
blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
items = ()


def encrypt(plaintext):
    """Encrypts data using AES-ECB and returns the ciphertext in binary format."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def decrypt(ciphertext):
    """Decrypts AES-ECB ciphertext in binary format and returns the original plaintext."""
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_plaintext, AES.block_size).decode()
    return plaintext


def main():
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody Management")
    parser.add_argument('command', choices=['add', 'checkout', 'checkin', 'show', 'remove', 'init', 'verify'],
                        help="Command to execute")
    parser.add_argument('-c', '--case_id', type=str, help="Case identifier (UUID)")
    parser.add_argument('-i', '--item_id', type=int, help="Item identifier (4-byte integer)")
    parser.add_argument('-g', '--creator', type=str, help="Creator of the evidence")
    parser.add_argument('-p', '--password', type=str, help="Password for authentication")
    parser.add_argument('-n', '--num_entries', type=int, help="Number of log entries to display")
    parser.add_argument('-r', '--reverse', action='store_true', help="Display history in reverse order")
    parser.add_argument('-y', '--reason', choices=['DISPOSED', 'DESTROYED', 'RELEASED'], help="Reason for removal")
    parser.add_argument('-o', '--owner', type=str, help="Owner information for RELEASED reason")
    args = parser.parse_args()

    if args.command == 'init':
        init_blockchain()
        sys.exit(1)
    elif args.command == 'add':
        add(args.case_id, args.item_id, args.creator, args.password)


def init_blockchain():
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')

    if not os.path.exists(blockchain_path):
        # Previous hash: 32 bytes of zeros
        prev_hash = b"0" * 32

        # Timestamp: current time as 8 bytes (big-endian unsigned long long)
        timestamp = 0

        # Case ID: 32 bytes of zeros
        case_id = b"0" * 32

        # Evidence ID: 32 bytes of zeros
        evidence_id = b"0" * 32

        # State: exactly 12 bytes, with 'INITIAL' and null-padded
        state = b"INITIAL\0\0\0\0\0"

        # Creator: 12 bytes of null bytes
        creator = b"\0" * 12

        # Owner: 12 bytes of null bytes
        owner = b"\0" * 12

        # Data: explicit null-terminated string
        data = b"Initial block\0"

        # Data length: 4 bytes representing length of data
        data_length = 14

        # Combine all fields exactly
        initial_block = struct.pack(
            "32s d 32s 32s 12s 12s 12s I",
            prev_hash,
            timestamp,
            case_id,
            evidence_id,
            state,
            creator,
            owner,
            data_length,
        )
        initial_block += data

        # Write to file
        with open(blockchain_path, 'wb') as file:
            file.write(initial_block)

        print("Blockchain initialized.")
    else:
        with open(blockchain_path, 'rb') as file:
            block_data = file.read()

        # Validate the initial block with strict checks
        if (block_data[:32] != b'\x00' * 32 or
                block_data[40:72] != b'0' * 32 or
                block_data[72:104] != b'0' * 32 or
                block_data[104:116] != b'INITIAL\0\0\0\0\0' or
                block_data[116:128] != b'\0' * 12 or
                block_data[128:140] != b'\0' * 12):
            print('Blockchain file invalid.')
            sys.exit(1)

        data_length = int.from_bytes(block_data[140:144], byteorder='big')
        if data_length != 14:
            print('Blockchain file invalid.')
            sys.exit(0)

        data = block_data[144:144 + data_length]
        if data != b'Initial block\0':
            print('Blockchain file invalid.')
            sys.exit(0)

        print("Blockchain file found with INITIAL block.")


def add(case_id, item_id, creator, password):
    case_id = encrypt(uuid.UUID(case_id).int.to_bytes(16, byteorder='big'))
    state = b'CHECKEDIN'
    owner = b'\x00' * 12
    creator = creator.encode('utf-8').ljust(12, b'\0')
    timestamp = time.time()
    blockchain_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')
    if not os.path.exists(blockchain_path):
        init_blockchain()
        sys.exit(0)

    for i in range(item_id):
        if item_id[i] in items:
            print(f"Duplicate item ID {item_id} for case ID {case_id}.")
            sys.exit(1)
    with open(blockchain_path, "rb") as file:
        file.seek(-128, os.SEEK_END)
        last_block = file.read(128)
    prev_hash = hashlib.sha256(last_block).digest()
    print(len(item_id))
    for i in range(item_id):
        data_length = 0
        evidence_id = encrypt(int(item_id[i]).to_bytes(16,byteorder='big'))
        new_block = struct.pack('32s d 32s 32s 12s 12s 12s I', prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length)
        with open(blockchain_path,"rb") as file:
            file.write(new_block)
            prev_hash = hashlib.sha256(new_block).digest()
            print(f'> Added item: {decrypt(evidence_id)}')
            print('> Status: CHECKEDIN')
            print(f'> Time of action: {datetime.datetime.fromtimestamp(timestamp).isoformat()}Z')




if __name__ == "__main__":
    main()
