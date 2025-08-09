# pragma version 0.4.3

from snekmate.utils import multicall as mc

signers: public(DynArray[address, 100]) # Signers max length must be bind because of language limitations
threshold: public(uint256)

signer_security_nonce: HashMap[address, uint256] # Used to erase signatures of signers when leaving and re-adding them
signed: HashMap[bytes32, bool]


BATCH_VALUE_SIZE: constant(uint256) = 32 + 32 + 32 + 32 + 1_024  # keccak + target + allow_failure + value + calldata
SIGNED_HASH_SIZE: constant(uint256) = 32 + 32  # nonce + signer address

@deploy
def __init__(threshold: uint256, signers: DynArray[address, 100]):
    assert threshold > 0, "Threshold must be greater than 0"
    assert len(signers) >= threshold, "Number of signers must be greater than threshold"

    for key: address in signers:
        assert key != empty(address), "Signer address must not be Zero"
        assert key not in self.signers, "Signers must be unique"
        self.signers.append(key)
    self.threshold = threshold

@view
@internal
def keccak_signer(nonce: uint256, signer: address) -> bytes32:
    return keccak256(
        concat(
            convert(nonce, bytes32),
            convert(signer, bytes32),
            convert(self.signer_security_nonce[signer], bytes32)
            )
        )

@internal
def reset_signatures(nonce: uint256):
    for signer: address in self.signers:
        self.signed[self.keccak_signer(nonce, signer)] = False

@view
@external
def keccak_multi_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256) -> bytes32:
    return self._keccak_multi_transaction(transaction, nonce)

@view
@internal
def _keccak_multi_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256) -> bytes32:
    data: Bytes[BATCH_VALUE_SIZE] = empty(Bytes[BATCH_VALUE_SIZE])
    keccak: bytes32 = keccak256(
            convert(nonce, bytes32)
        )
    # Iterate over the transaction and calculate the keccak hash
    for t: mc.BatchValue in transaction:
        data = concat(
            keccak,
            convert(t.target, bytes32),
            convert(t.allow_failure, bytes32),
            convert(t.value, bytes32),
            t.calldata
        )
        keccak = keccak256(data)
    return keccak

@view
@external
def count_signatures(nonce: uint256) -> uint256:
    return self._count_signatures(nonce)

@view
@internal
def _count_signatures(nonce: uint256) -> uint256:
    count: uint256 = 0
    for signer: address in self.signers:
        if self.signed[self.keccak_signer(nonce, signer)]:
            count = unsafe_add(count, 1) # Count is much larger than the amount of signers so no overflow
    return count


@view
@external
def get_threshold() -> uint256:
    return self.threshold

@view
@external
def get_signers() -> DynArray[address, 100]:
    return self.signers

@external
def set_threshold(_threshold: uint256):
    assert msg.sender == self, "Only callable using send_multi_transaction"
    assert _threshold > 0, "Threshold must be greater than 0"
    assert _threshold <= len(self.signers), "Threshold must be less than or equal to the number of signers"
    self.threshold = _threshold

@external
def add_signer(_signer: address):
    assert msg.sender == self, "Only callable using send_multi_transaction"
    assert _signer != empty(address), "Signer address must not be Zero"
    assert _signer not in self.signers, "Signer already exists"
    assert len(self.signers) < 100, "Maximum number of signers is 100"
    self.signers.append(_signer)
    self.signer_security_nonce[_signer] = block.number

@external
def remove_signer(_signer: address):
    assert msg.sender == self, "Only callable using send_multi_transaction"
    assert _signer != empty(address), "Signer address must not be Zero"
    assert _signer in self.signers, "Address not a signer"
    assert self.threshold < len(self.signers), "Cannot make threshold greater than number of signers"

    # Remove the signer from the signers list
    for i: uint256 in range(len(self.signers), bound=100):
        if self.signers[i] == _signer:
            self.signers[i] = self.signers[unsafe_sub(len(self.signers), 1)] # Number of signers cannot be 0 before running this function so no overflow
            self.signers.pop()
            break

@external
def sign_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256):
    assert msg.sender in self.signers, "Sender not a signer"
    assert not self.signed[self.keccak_signer(nonce, msg.sender)], "Sender already signed"

    keccak: bytes32 = self._keccak_multi_transaction(transaction, nonce)
    self.signed[self.keccak_signer(nonce, msg.sender)] = True

@external
def reject_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256):
    assert msg.sender in self.signers, "Sender not a signer"
    assert self.signed[self.keccak_signer(nonce, msg.sender)], "Sender has not signed the transaction"
    keccak: bytes32 = self._keccak_multi_transaction(transaction, nonce)
    self.signed[self.keccak_signer(nonce, msg.sender)] = False


@external
@payable
def send_multi_transaction(transaction: DynArray[mc.BatchValue, mc._DYNARRAY_BOUND], nonce: uint256) -> DynArray[mc.Result, mc._DYNARRAY_BOUND]:
    assert msg.sender in self.signers, "Sender not a signer"
    assert self.threshold <= self._count_signatures(nonce), "Not enough signatures"
    self.reset_signatures(nonce)
    return mc._multicall_value(transaction)