# pragma version 0.4.3

from snekmate.utils import multicall as mc

signers: DynArray[address, 100] # Signers max length must be bind because of language limitations
signer_security_nonce: HashMap[address, uint256] # Used to erase signatures of signers when leaving and re-adding them
signed: HashMap[bytes32, bool]
transaction_keccak: HashMap[uint256, bytes32]

threshold: uint256

BATCH_VALUE_SIZE: constant(uint256) = 32 + 32 + 32 + 32 + 1_024  # keccak + target + allow_failure + value + calldata
SIGNED_HASH_SIZE: constant(uint256) = 32 + 32  # nonce + signer address

@deploy
def __init__(threshold: uint256, signers: DynArray[address, 100]):
    assert threshold > 0, "Threshold must be greater than 0"
    assert len(signers) >= threshold, "Number of signers must be greater than threshold"
    assert len(signers) <= 100, "Maximum number of signers is 100"
    for key: address in signers:
        assert key != empty(address), "Signer address must not be Zero"
        assert key not in self.signers, "Signers must be unique"
        self.signers.append(key)
    self.threshold = threshold

@view
@internal
def keccak_signer(nonce: uint256, signer: address) -> bytes32:
    return keccak256(concat(convert(nonce, bytes32), convert(signer, bytes32), convert(self.signer_security_nonce[signer], bytes32)))

@view
@internal
def keccak_multi_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256) -> bytes32:
    data: Bytes[BATCH_VALUE_SIZE] = empty(Bytes[BATCH_VALUE_SIZE])
    # Use the nonce and the contract address for replay protection
    keccak: bytes32 = keccak256(concat(convert(self, bytes32), convert(nonce, bytes32)))
    # Iterate over the transaction and calculate the keccak hash
    for t: mc.BatchValue in transaction:
        data = concat(keccak, convert(t.target, bytes32), convert(t.allow_failure, bytes32), convert(t.value, bytes32), t.calldata)
        keccak = keccak256(data)
    return keccak

@view
@internal
def count_signatures(nonce: uint256) -> uint256:
    count: uint256 = 0
    for key: address in self.signers:
        if self.signed[self.keccak_signer(nonce, key)]:
            count += 1
    return count

@internal
def reset_signatures(nonce: uint256):
    for key: address in self.signers:
        self.signed[self.keccak_signer(nonce, key)] = False

@view
@external
def get_threshold() -> uint256:
    return self.threshold

@view
@external
def get_signers() -> DynArray[address, 100]:
    return self.signers

@external
def add_signer(_signer: address):
    assert msg.sender == self, "Only callable from contract call"
    assert _signer != empty(address), "Signer address must not be Zero"
    assert _signer not in self.signers, "Signer already exists"
    assert len(self.signers) < 100, "Maximum number of signers is 100"
    self.signers.append(_signer)
    self.signer_security_nonce[_signer] = block.number

@external
def remove_signer(_signer: address):
    assert msg.sender == self, "Only callable from contract call"
    assert _signer != empty(address), "Signer address must not be Zero"
    assert _signer in self.signers, "Address not a signer"
    assert self.threshold < len(self.signers), "Cannot make threshold greater than number of signers"
    signer_index: uint256 = 0

    # Find the index of the signer to be removed
    for i: uint256 in range(len(self.signers), bound=100):
        if self.signers[i] == _signer:
            signer_index = i
            break

    # Remove the signer from the signers list
    self.signers[signer_index] = self.signers[len(self.signers) - 1]
    self.signers.pop()

@external
def sign_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256):
    assert msg.sender in self.signers, "Sender not a signer"
    assert not self.signed[self.keccak_signer(nonce, msg.sender)], "Sender already signed"

    keccak: bytes32 = self.keccak_multi_transaction(transaction, nonce)
    if self.transaction_keccak[nonce] != empty(bytes32):
        assert keccak == self.transaction_keccak[nonce], "Transaction keccak does not match the expected value"
    else:
        self.transaction_keccak[nonce] = keccak
    self.signed[self.keccak_signer(nonce, msg.sender)] = True

@external
def reject_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256):
    assert msg.sender in self.signers, "Sender not a signer"
    assert self.signed[self.keccak_signer(nonce, msg.sender)], "Sender has not signed the transaction"
    
    keccak: bytes32 = self.keccak_multi_transaction(transaction, nonce)
    assert keccak == self.transaction_keccak[nonce], "Transaction keccak does not match the expected value"
    
    self.signed[self.keccak_signer(nonce, msg.sender)] = False
    

@external
@payable
def send_multi_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256) -> DynArray[mc.Result, mc._DYNARRAY_BOUND]:
    assert msg.sender in self.signers, "Sender not a signer"
    assert self.threshold <= self.count_signatures(nonce), "Not enough signatures"
    self.reset_signatures(nonce)
    return mc._multicall_value(transaction)