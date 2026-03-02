from snark_lib import *
from utils.hash import *


def main():
    a = NONRESERVED_PROGRAM_INPUT_START
    b = a + 8
    res = compute_commitment(a, b)  # type: ignore[reportCallIssue]
    for i in range(0, 8):
        print(res[i])
    return
