from snark_lib import *


def dual_mux(a, b, switch):
    # asserts switch is 0 or 1
    assert switch[0] * (1 - switch[0]) == 0
    c = (b - a) * switch[0] + a
    d = (a - b) * switch[0] + b
    return c, d


def verify_path(levels: Const, leaf, leaf_sibling, is_right_child, root):
    node = Array(8)
    l, r = dual_mux(leaf, leaf_sibling, is_right_child)
    poseidon16(l, r, node)  # type: ignore[reportCallIssue]

    sibling: Mut
    flag: Mut
    sibling = is_right_child + 1

    flag = sibling + 8
    path = DynArray([])

    for _ in unroll(0, levels):
        path_node = Array(8)
        l, r = dual_mux(node, sibling, flag)
        poseidon16(l, r, path_node)  # type: ignore[reportCallIssue]
        sibling = flag + 1
        flag = sibling + 8
        path.push(path_node)

    final_node = path[0]
    for i in unroll(0, 8):
        assert root[i] == final_node[i]
    return
