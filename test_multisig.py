import pytest
import boa
from dataclasses import dataclass
from web3 import Web3
from eth_abi import encode
from eth_utils import function_signature_to_4byte_selector

@dataclass
class BatchValue:
    target: str
    allow_failure: bool
    value: int
    calldata: bytes

single_tx = BatchValue(
        target=Web3.to_checksum_address("0x000000000000000000000000000000000000dead"),
        allow_failure=False,
        value=1000,
        calldata=b"0"
    )
boa.env.set_balance(Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F"), 1_000_000_000_000_000_000)

@pytest.fixture
def contract():
    return boa.load("multisig.vy", 1, [Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F"), Web3.to_checksum_address("0x000000000000000000000000000000000000dead")])

@pytest.fixture
def contract_two_threshold():
    return boa.load("multisig.vy", 2, [Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F"), Web3.to_checksum_address("0x000000000000000000000000000000000000dead")])

# deploy tests
def test_deploy_valid():
    signers = [Web3.to_checksum_address(f"0x{'%040x' % i}") for i in range(1, 4)]
    threshold = 2
    ms = boa.load("multisig.vy", threshold, signers)
    assert ms.get_threshold() == threshold
    assert ms.get_signers() == signers

def test_deploy_threshold_zero():
    signers = [Web3.to_checksum_address(f"0x{'%040x' % i}") for i in range(1, 4)]
    with pytest.raises(boa.BoaError, match="Threshold must be greater than 0"):
        boa.load("multisig.vy", 0, signers)

def test_deploy_threshold_greater_than_signers():
    signers = [Web3.to_checksum_address(f"0x{'%040x' % i}") for i in range(1, 3)]
    threshold = 10
    with pytest.raises(boa.BoaError, match="Number of signers must be greater than threshold"):
        boa.load("multisig.vy", threshold, signers)

def test_deploy_signers_more_than_100():
    signers = [Web3.to_checksum_address(f"0x{'%040x' % i}") for i in range(1, 102)]
    threshold = 2
    with pytest.raises(boa.BoaError):
        boa.load("multisig.vy", threshold, signers)

def test_deploy_signers_not_unique():
    signer = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")
    signers = [signer, signer, Web3.to_checksum_address("0x0000000000000000000000000000000000000002")]
    threshold = 2
    with pytest.raises(boa.BoaError):
        boa.load("multisig.vy", threshold, signers)

def test_deploy_signer_is_zero_address():
    signers = [Web3.to_checksum_address("0x0000000000000000000000000000000000000000"), Web3.to_checksum_address("0x0000000000000000000000000000000000000002")]
    threshold = 1
    with pytest.raises(boa.BoaError, match="Signer address must not be Zero"):
        boa.load("multisig.vy", threshold, signers)


# test sign transaction

def test_sign_transaction_one_batch(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]

    contract.sign_transaction(batch, 0)

def test_sign_transaction_big_batch(contract):

    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx] * 10]

    contract.sign_transaction(batch, 0)

def test_sign_transaction_invalid_sender(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]

    with pytest.raises(boa.BoaError, match="Sender not a signer"):
        contract.sign_transaction(batch, 0, sender=Web3.to_checksum_address("0x0000000000000000000000000000000000000001"))

def test_sign_transaction_already_signed(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]

    contract.sign_transaction(batch, 0)
    
    with pytest.raises(boa.BoaError, match="Sender already signed"):
        contract.sign_transaction(batch, 0)

# test send multi transaction
def test_send_multi_transaction_valid(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]
    nonce = 0
    contract.sign_transaction(batch, nonce)
    contract.send_multi_transaction(batch, nonce, value=1000)

    assert boa.env.get_balance(Web3.to_checksum_address("0x000000000000000000000000000000000000dead")) == 1000

def test_send_multiple_transactions_valid(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]
    nonce = 0
    contract.sign_transaction(batch, nonce)

    contract.send_multi_transaction(batch, nonce, value=1000)
    assert boa.env.get_balance(Web3.to_checksum_address("0x000000000000000000000000000000000000dead")) == 1000

    contract.sign_transaction(batch, nonce+1)
    contract.send_multi_transaction(batch, nonce+1, value=1000)
    assert boa.env.get_balance(Web3.to_checksum_address("0x000000000000000000000000000000000000dead")) == 2000

def test_send_multi_transaction_invalid_sender(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]

    nonce = 0
    contract.sign_transaction(batch, nonce)

    with pytest.raises(boa.BoaError, match="Sender not a signer"):
        contract.send_multi_transaction(batch, nonce, sender=Web3.to_checksum_address("0x0000000000000000000000000000000000000001"))

def test_send_multi_transaction_not_enough_signatures(contract):
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [single_tx]]

    with pytest.raises(boa.BoaError, match="Not enough signatures"):
        contract.send_multi_transaction(batch, 0)


# test add signer
def test_add_signer_valid(contract):
    new_signer = Web3.to_checksum_address("0x0000000000000000000000000000000000000002")
    contract.add_signer(new_signer, sender=contract.address)
    assert contract.get_signers()[-1] == new_signer, "New signer not added correctly"

def test_add_signer_duplicate_signer(contract):
    new_signer = Web3.to_checksum_address("0x0000000000000000000000000000000000000002")
    contract.add_signer(new_signer, sender=contract.address)

    with pytest.raises(boa.BoaError, match="Signer already exists"):
        contract.add_signer(new_signer, sender=contract.address)

def test_add_signer_zero_address(contract):
    new_signer = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
    with pytest.raises(boa.BoaError, match="Signer address must not be Zero"):
        contract.add_signer(new_signer, sender=contract.address)

#test remove signer
def test_remove_signer_valid(contract):
    signer_to_remove = Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F")
    contract.remove_signer(signer_to_remove, sender=contract.address)
    assert signer_to_remove not in contract.get_signers(), "Signer not removed correctly"

# test reject transaction
def test_reject_transaction_not_a_signer(contract):
    batch = [(contract.address, False, 0, b"")]
    nonce = 42
    with pytest.raises(boa.BoaError, match="Sender not a signer"):
        contract.reject_transaction(batch, nonce, sender=Web3.to_checksum_address("0x0000000000000000000000000000000000000001"))

def test_reject_transaction_not_signed(contract):
    batch = [(contract.address, False, 0, b"")]
    nonce = 43
    # Sender is a signer but has not signed
    with pytest.raises(boa.BoaError, match="Sender has not signed the transaction"):
        contract.reject_transaction(batch, nonce, sender=Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F"))

def test_reject_transaction_success(contract):
    batch = [(contract.address, False, 0, b"")]
    nonce = 44
    signer = Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F")
    # First, sign the transaction
    contract.sign_transaction(batch, nonce, sender=signer)
    # Now, reject the transaction
    contract.reject_transaction(batch, nonce, sender=signer)
    # Try to reject again, should fail
    with pytest.raises(boa.BoaError, match="Sender has not signed the transaction"):
        contract.reject_transaction(batch, nonce, sender=signer)

# test set threshold
def test_set_threshold_eoa_call(contract):
    with pytest.raises(boa.BoaError, match="Only callable using send_multi_transaction"):
        contract.set_threshold(2, sender=Web3.to_checksum_address("0x0000000000000000000000000000000000000001"))

def test_set_threshold_zero(contract):
    with pytest.raises(boa.BoaError, match="Threshold must be greater than 0"):
        contract.set_threshold(0, sender=contract.address)

def test_set_threshold_greater_than_signers(contract):
    num_signers = len(contract.get_signers())
    with pytest.raises(boa.BoaError, match="Threshold must be less than or equal to the number of signers"):
        contract.set_threshold(num_signers + 1, sender=contract.address)

def test_set_threshold_valid(contract):
    contract.set_threshold(1, sender=contract.address)
    assert contract.get_threshold() == 1
    contract.set_threshold(len(contract.get_signers()), sender=contract.address)
    assert contract.get_threshold() == len(contract.get_signers())


# test full flows

def test_remove_signer_using_multicall_batch(contract):
    selector = function_signature_to_4byte_selector("remove_signer(address)")
    encoded_args = encode(['address'], [Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F")])
    batch = BatchValue(
        target=Web3.to_checksum_address(contract.address),
        allow_failure=False,
        value=0,
        calldata=selector + encoded_args
    )
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [batch]]
    nonce = 0
    contract.sign_transaction(batch, nonce, sender=Web3.to_checksum_address("0x000000000000000000000000000000000000dead"))
    contract.send_multi_transaction(batch, nonce, sender=Web3.to_checksum_address("0x000000000000000000000000000000000000dead"))
    assert Web3.to_checksum_address("0x00dE89C733555886f785b0C32b498300297e481F") not in contract.get_signers(), "Signer not removed correctly using multicall batch"

def test_add_signer_using_multicall_batch(contract):
    new_signer = Web3.to_checksum_address("0x0000000000000000000000000000000000000002")
    selector = function_signature_to_4byte_selector("add_signer(address)")
    encoded_args = encode(['address'], [new_signer])
    batch = BatchValue(
        target=Web3.to_checksum_address(contract.address),
        allow_failure=False,
        value=0,
        calldata=selector + encoded_args
    )
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [batch]]
    nonce = 0
    contract.sign_transaction(batch, nonce)
    contract.send_multi_transaction(batch, nonce)
    assert new_signer in contract.get_signers(), "New signer not added correctly using multicall batch"

def test_set_threshold_using_multicall_batch(contract):
    new_threshold = 1
    selector = function_signature_to_4byte_selector("set_threshold(uint256)")
    encoded_args = encode(['uint256'], [new_threshold])
    batch = BatchValue(
        target=Web3.to_checksum_address(contract.address),
        allow_failure=False,
        value=0,
        calldata=selector + encoded_args
    )
    batch = [(b.target, b.allow_failure, b.value, b.calldata) for b in [batch]]
    nonce = 0
    contract.sign_transaction(batch, nonce)
    contract.send_multi_transaction(batch, nonce)
    assert contract.get_threshold() == new_threshold, "Threshold not set correctly using multicall batch"