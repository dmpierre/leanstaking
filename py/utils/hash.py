from snark_lib import *


def compute_commitment(nullifier, secret):
    commitment = Array(8)
    poseidon16(nullifier, secret, commitment)
    return commitment


def compute_nullifier_hash(nullifier):
    nullifier_hash = Array(8)
    poseidon16(nullifier, nullifier, nullifier_hash)
    return nullifier_hash
