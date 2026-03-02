use super::{MerklePath, MerkleProof};
use lean_vm::F;

/*
 *                                                  |root|
 *              |node_1|                                                     |node_2|
 * [commitment]           commit([11; 8], [13; 8])       commit([17; 8], [19; 8])  commit([23; 8], [29;8])
 *   ^^^ proving this one
*/
pub fn two_levels_merkle_proof() -> MerkleProof {
    let path = MerklePath {
        // poseidon16(commit(17, 19), commit(23, 29))
        auth_path: vec![[
            F::new(300284318),
            F::new(184251726),
            F::new(785324177),
            F::new(1645200318),
            F::new(218255519),
            F::new(324974344),
            F::new(38180562),
            F::new(1122512566),
        ]],
        // commitment(11, 13)
        leaf_sibling: [
            F::new(1071247239),
            F::new(306727947),
            F::new(1171256860),
            F::new(1640919826),
            F::new(785163668),
            F::new(1285575607),
            F::new(557881172),
            F::new(1283880189),
        ],
        flags: vec![F::new(0)],
        leaf_is_right_child: F::new(0),
    };
    let proof = MerkleProof {
        root: [
            F::new(918934911),
            F::new(1615771358),
            F::new(1781687901),
            F::new(450006695),
            F::new(716307122),
            F::new(697919692),
            F::new(1249286800),
            F::new(1473571382),
        ],
        path: path,
    };
    return proof;
}
