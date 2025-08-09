# Multisig Smart Contract (Vyper)

## Overview

This contract implements a simple multisignature wallet in Vyper, designed for secure and flexible management. It allows a group of signers to collectively authorize and execute transactions, with a configurable threshold for required approvals.

## Features

- **Configurable Signers and Threshold:**
  - Up to 100 unique signers.
  - Threshold must be > 0 and ≤ number of signers.
- **Batch Transaction Support:**
  - Efficiently execute multiple calls in a single transaction using multicall.
- **Signature Management:**
  - Each signer can sign or reject transactions for a given nonce.
  - Signatures are tracked per signer and nonce.
- **Signer Management:**
  - Add or remove signers via contract call (requires multisig approval).
  - Security nonce ensures signature invalidation when a signer is removed and re-added.
- **Threshold Management:**
  - Change threshold via contract call (requires multisig approval).

## Contract Functions

### Deployment
- `__init__(threshold: uint256, signers: DynArray[address, 100])`
  - Initializes the contract with a threshold and a list of unique signers.

### Transaction Signing
- `sign_transaction(transaction, nonce)`
  - Allows a signer to sign a batch transaction for a specific nonce.
- `reject_transaction(transaction, nonce)`
  - Allows a signer to revoke their signature for a specific transaction and nonce.
- `send_multi_transaction(transaction, nonce)`
  - Executes a batch transaction if enough signatures are collected.

### Signer Management
- `add_signer(_signer)`
  - Adds a new signer (must be called by contract itself).
- `remove_signer(_signer)`
  - Removes a signer (must be called by contract itself).

### Threshold Management
- `set_threshold(_threshold)`
  - Updates the signature threshold (must be called by contract itself).

### Views
- `get_signers()`
  - Returns the current list of signers.
- `get_threshold()`
  - Returns the current threshold.
- `count_signatures(nonce)`
  - Returns the number of signatures for a given nonce.
- `keccak_multi_transaction(transaction, nonce)`
  - Returns the keccak hash for a batch transaction and nonce.


## Security Considerations

- Signer security nonce ensures that signatures are invalidated if a signer is removed and re-added.
- All critical checks (unique signers, non-zero addresses, threshold limits) are enforced at the contract level.
- Signatures are collected on-chain and use the message sender, therefor there is no replay attacks

## Testing

Extensive unit tests are provided in `test_multisig.py` covering:
- Deployment edge cases (invalid threshold, duplicate signers, zero address, etc.)
- Transaction signing and rejection
- Batch execution
- Signer and threshold management
- Security checks and error handling

## Requirements

- Vyper >= 0.4.3
- [snekmate multicall utils](https://github.com/pcaversaccio/snekmate)
- See `requirements.txt` for Python dependencies for testing

## Example

```python
# Example: Deploying and using the multisig contract
signers = ["0x...", "0x..."]
threshold = 2
ms = boa.load("multisig.vy", threshold, signers)

# Sign a transaction
ms.sign_transaction(batch, nonce, sender=signers[0])

# Execute batch if enough signatures
ms.send_multi_transaction(batch, nonce, value=1000)
```

## On-Chain Authorization

All transaction approvals and rejections are performed on-chain. This ensures:
- Full transparency: All signatures, approvals, and rejections are recorded on the blockchain.
- Security: Only authorized signers can approve or reject transactions, and all actions are verifiable and immutable.
- Decentralized control: No off-chain coordination is required; all multisig logic is enforced by the smart contract.

## License

MIT
