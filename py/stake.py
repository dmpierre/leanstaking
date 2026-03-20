
from snark_lib import *
from utils.hash import *
from utils.merkle import *


def main():
    levels = 1
    nullifier_preimage = NONRESERVED_PROGRAM_INPUT_START
    validator_key = nullifier_preimage + 8
    withdrawal_cred = validator_key + 13
    amount = withdrawal_cred + 9
    commitment = compute_commitment(
        nullifier_preimage, validator_key, withdrawal_cred, amount)
    nullifier = compute_nullifier(nullifier_preimage)
    # TODO: assert nullifier, validator_key, withdrawal_cred, and amount match public inputs
    leaf_sibling = amount + 1
    leaf_is_right_child = leaf_sibling + 8
    root = leaf_is_right_child + 10 * levels
    verify_path(levels, commitment, leaf_sibling, leaf_is_right_child, root)
    return
