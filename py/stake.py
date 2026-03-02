
from snark_lib import *
from utils.hash import *
from utils.merkle import *


def main():
    levels = 1
    secret = NONRESERVED_PROGRAM_INPUT_START
    nullifier = secret + 8
    commitment = compute_commitment(nullifier, secret)
    nullifier_hash = compute_nullifier_hash(nullifier)
    leaf_sibling = nullifier + 8
    leaf_is_right_child = leaf_sibling + 8
    root = leaf_is_right_child + 10 * levels
    verify_path(levels, commitment, leaf_sibling, leaf_is_right_child, root)
    return
