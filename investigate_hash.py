#!/usr/bin/env python3
"""
Investigation script to find the problematic hash in transaction test data.
This helps understand why the account was never created as an output.
"""

import json
import os
import sys
from pathlib import Path

def search_hash_in_transaction_files(test_name, target_hash):
    """Search for a specific hash in all transaction files."""
    base_path = Path("tests/data/transactions") / test_name

    if not base_path.exists():
        print(f"Error: Test data directory {base_path} does not exist")
        return

    print(f"Searching for hash '{target_hash}' in {test_name} transaction files...")
    print(f"Directory: {base_path}")
    print("-" * 80)

    found_files = []
    total_files = 0

    # Get all JSON files and sort them
    json_files = sorted([f for f in base_path.iterdir() if f.suffix == '.json'])

    for file_path in json_files:
        total_files += 1
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Simple string search first
            if target_hash in content:
                found_files.append(file_path.name)
                print(f"✓ Found in: {file_path.name}")

                # Parse JSON to get more details
                try:
                    data = json.loads(content)

                    # Check meta for account keys
                    if 'meta' in data and 'postTokenBalances' in data['meta']:
                        for balance in data['meta']['postTokenBalances']:
                            if 'mint' in balance and target_hash in str(balance):
                                print(f"  - Found in postTokenBalances: {balance}")

                    if 'meta' in data and 'preTokenBalances' in data['meta']:
                        for balance in data['meta']['preTokenBalances']:
                            if 'mint' in balance and target_hash in str(balance):
                                print(f"  - Found in preTokenBalances: {balance}")

                    # Check transaction details
                    if 'transaction' in data:
                        tx = data['transaction']
                        if 'message' in tx and 'accountKeys' in tx['message']:
                            for i, key in enumerate(tx['message']['accountKeys']):
                                if target_hash in str(key):
                                    print(f"  - Found in accountKeys[{i}]: {key}")

                    print(f"  - Slot: {data.get('slot', 'unknown')}")
                    print(f"  - Block time: {data.get('blockTime', 'unknown')}")

                except json.JSONDecodeError as e:
                    print(f"  - Warning: Could not parse JSON in {file_path.name}: {e}")

                print()

        except Exception as e:
            print(f"Error reading {file_path.name}: {e}")

    print("-" * 80)
    print(f"Search complete. Found in {len(found_files)} out of {total_files} files.")

    if found_files:
        print(f"Files containing the hash: {', '.join(found_files)}")
    else:
        print("Hash not found in any transaction files!")
        print("This could indicate:")
        print("  1. The hash is calculated incorrectly")
        print("  2. The transaction that creates this account is missing from test data")
        print("  3. The account is created in a different format/encoding")

def analyze_transaction_order(test_name):
    """Analyze the transaction order to understand the UTXO flow."""
    base_path = Path("tests/data/transactions") / test_name

    if not base_path.exists():
        print(f"Error: Test data directory {base_path} does not exist")
        return

    transactions = []

    # Get all JSON files and extract slot information
    for file_path in base_path.iterdir():
        if file_path.suffix == '.json':
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                slot = data.get('slot', 0)
                transactions.append((slot, file_path.name, data))
            except Exception as e:
                print(f"Error reading {file_path.name}: {e}")

    # Sort by slot
    transactions.sort(key=lambda x: x[0])

    print(f"\nTransaction order analysis for {test_name}:")
    print(f"Total transactions: {len(transactions)}")
    print("First 10 transactions:")
    for i, (slot, filename, data) in enumerate(transactions[:10]):
        print(f"  {i+1:2d}. Slot {slot:8d}: {filename}")

    print("\nLast 10 transactions:")
    for i, (slot, filename, data) in enumerate(transactions[-10:], len(transactions)-9):
        print(f"  {i:2d}. Slot {slot:8d}: {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python investigate_hash.py <target_hash> [test_name]")
        print("Example: python investigate_hash.py 2Xsgq4nsAx4eoJGujF5UD9zVzhB7UaAW6WrhKLeQDukX")
        sys.exit(1)

    target_hash = sys.argv[1]
    test_name = sys.argv[2] if len(sys.argv) > 2 else "txs_8bAVNbY2KtCsLZSGFRQ9s44p1sewzLz68q7DLFsBannh"

    print(f"Investigating hash: {target_hash}")
    print(f"Test name: {test_name}")
    print("=" * 80)

    # Search for the hash in transaction files
    search_hash_in_transaction_files(test_name, target_hash)

    # Analyze transaction order
    analyze_transaction_order(test_name)

if __name__ == "__main__":
    main()
