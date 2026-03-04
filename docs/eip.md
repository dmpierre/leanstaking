---
eip: 
title: Lean Staking 
description: 
author:
discussions-to: 
status: 
type:
category:
created:
requires: EIP-7864
---

## Abstract

"Lean Staking" is an L1 native, two-phase, staking process providing validator unlinkability. Lean staking can be made post-quantum secure provided the underlying proving system is. We provide an example LeanVM implementation. Implementing Lean Staking does not require any CL change and remains optional for validators.

The current draft does not enforce a specific hash function or field, since both will be strongly tied to the chosen underlying proving system. 

We provide an implementation using LeanVM. It uses Poseidon2 over the degree 5 of the Koala-Bear field. LeanVM is an ongoing Ethereum Foundation project to provide a formally verified, post-quantum ready proving system.

## Motivation

Privacy is a pressing requirement for Ethereum. L1's staking in Ethereum economic and security powerhouse. At the time of this EIP, the staking contract locks more than 81 million ETH ($167B). However, the current staking flow is fully public, linking together deposit and validator keys. This lack of privacy compromises solo and institutional stakers alike, sometimes putting their funds and even physical safety at risk.  

Breaking the link between execution layer (EL) and consensus layer (CL) credentials would provide a powerful base layer privacy provisioning protocol.

We propose "Lean Staking". It provides "validator unlinkability", i.e. the ability to uncouple validators consensus layer (CL) keys from their corresponding execution layer (EL) deposit address. With [EIP-6110](https://eips.ethereum.org/EIPS/eip-6110) the responsibility of deposit inclusion and validation has shifted to the execution layer, such that Lean Staking requires a minimal amount of changes only on the staking contract.

## Specification

### Pool Tree

We add a "Pool Tree" to the staking contract. The pool tree SHOULD be a binary merkle tree, where each leaf stores a 32 bytes value corresponding to a cryptographic commitment. The pool tree SHOULD be SNARK friendly to provide the ability to generate zero-knowledge inclusion proofs on resource-constrained devices. The staking contract MUST store all pool tree roots resulting from leaf updates.

An interesting line of work is [EIP-7864](./)'s effort to migrate Ethereum's state tree to a binary SNARK-friendly tree in order to generate succint chain-validity proofs.

### Pool 

To start unlinking with Lean Staking, the validator MUST send ETH alongside a cryptographic commitment to the staking contract. To do this, we update the staking contract, which now MUST contain a method providing the ability for validators to update the pool tree with their  commitment. 

The method to add a commitment to the pool tree along a ETH deposit SHOULD be named `pool`. Calling `pool` MUST NOT lead to the deposit being added to the deposit requests list. In this draft, we recommend that entering the pool MUST require a specific ETH amount, following the 32 ETH increments required for staking. 

```solidity
function pool(bytes32 commitment) external payable {
  require(msg.value >= 32 ether);
  bytes32 newRoot = insertLeaf(root, commitment);
  storeRoot(newRoot)
  emit PoolCommitment(commitment, commitmentCount - 1);
}
```

Upon providing a correctly formatted commitment and ETH amount, it MUST lead to the commitment being included within the pool tree and the storing of the updated pool tree root. It SHOULD emit a `PoolCommitment` event.

### zkSNARK 

The zkSNARK MUST attest in zk to the knowledge of an unclaimed commitment in one of the stored pool tree root and whose public nullifier hash is `nullifier_hash`. We implement this deposit claiming program using LeanVM, a VM coupled with a post-quantum proving system based off a combination of WHIR and superspartan. LeanVM exposes a Poseidon2 precompile (`poseidon16`). For this implementation, we leverage this precompile to compute commitment, nullifier and the pool tree merkle path. 

```python
def compute_commitment(nullifier, secret):
    commitment = Array(8)
    poseidon16(nullifier, secret, commitment)
    return commitment

def compute_nullifier_hash(nullifier):
    nullifier_hash = Array(8)
    poseidon16(nullifier, nullifier, nullifier_hash)
    return nullifier_hash

def dual_mux(a, b, switch):
    # asserts switch is 0 or 1
    assert switch[0] * (1 - switch[0]) == 0
    c = (b - a) * switch[0] + a
    d = (a - b) * switch[0] + b
    return c, d

def verify_path(levels: Const, leaf, leaf_sibling, is_right_child, root):
    node = Array(8)
    l, r = dual_mux(leaf, leaf_sibling, is_right_child)
    poseidon16(l, r, node) 

    sibling: Mut
    flag: Mut
    sibling = is_right_child + 1

    flag = sibling + 8
    path = DynArray([])

    for _ in unroll(0, levels):
        path_node = Array(8)
        l, r = dual_mux(node, sibling, flag)
        poseidon16(l, r, path_node)
        sibling = flag + 1
        flag = sibling + 8
        path.push(path_node)

    final_node = path[0]
    for i in unroll(0, 8):
        assert root[i] == final_node[i]
    return

def main():
    levels = 1
    secret = NONRESERVED_PROGRAM_INPUT_START
    nullifier = secret + 8
    commitment = compute_commitment(nullifier, secret)
    nullifier_hash = compute_nullifier_hash(nullifier)
    # TODO: assert nullifier hash is correct
    leaf_sibling = nullifier + 8
    leaf_is_right_child = leaf_sibling + 8
    root = leaf_is_right_child + 10 * levels
    verify_path(levels, commitment, leaf_sibling, leaf_is_right_child, root)
    return
```

### Deposit 

We update the staking contract's deposit method. The `deposit` method MUST not be `payable`. A valid zkSNARK attesting to the knowledge of a non-nullified commitment MUST be provided for a validator to add its deposit to the deposit list. The staking contract MUST collect the correct amount of ETH from the corresponding pool tree. 

```solidity
function deposit(
    bytes calldata pubkey,
    bytes calldata withdrawal_credentials,
    bytes calldata signature,
    bytes32 deposit_data_root,
    Proof pool_proof
) external 

```
## Rationale

### Fixed Pool Amounts

It is possible to not require depositing a specific ETH amount. However, non-uniform pool deposits lead to trivial linking attacks, stemming from observing both the pool and deposit phases. Providing different trees for different amounts in increments of 32 ETH provides a compromise between flexibility and while providing a first protection layer for validators with respect to analytics-driven attacks.

### Binary Trees

Already in consideration with [EIP-7864](https://eips.ethereum.org/EIPS/eip-7864). Share work there. Probably use the same constants and re-use implementation effort (field, ). Storing tree roots prevents stakers from keeping track of all leaf updates which happened between the moment they pool and the moment the deposit. 

### No opt-out

We could allow validators who wish to opt out from unlinking to provide an empty proof while attaching its ETH deposit. However, we would like to encourage validator privacy hygiene and have the largest set of plausibly deniable validator deposits. Baking in an opt-out in the staking contract would decrease this set. Note that a validator could still signal by providing the initial address which initiated pooling as `withdrawal_credentials`.

## Security Considerations

## Post-quantum security

## Plausibly Deniable Transfers 

To enshrine privacy within the L1, Wormhole made possible base layer privacy with plausible deniability, but collision resistance problem due to 20 bytes addresses. Lean Staking offers a way to obtain for free a plausibly deniable transfer system. To do this, a depositor can provide the receiver's address as withdrawal credentials. An adversary observing the Ethereum deposit pool will have no advantage 


