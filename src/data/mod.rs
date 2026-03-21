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
            F::new(1214873956),
            F::new(258084305),
            F::new(2002146002),
            F::new(645480002),
            F::new(499722232),
            F::new(67463537),
            F::new(272555026),
            F::new(342163208),
        ],
        path: path,
    };
    return proof;
}

/*
 *                                                  |root|
 *              |node_1|                                                     |node_2|
 * [commitment]           commit([11; 8], [13; 8])       commit([17; 8], [19; 8])  commit([23; 8], [29;8])
 *   ^^^ proving this one
*/
pub fn three_levels_merkle_proof() -> MerkleProof {
    let path = MerklePath {
        // poseidon16(commit(17, 19), commit(23, 29))
        auth_path: vec![
            [
                F::new(300284318),
                F::new(184251726),
                F::new(785324177),
                F::new(1645200318),
                F::new(218255519),
                F::new(324974344),
                F::new(38180562),
                F::new(1122512566),
            ],
            [
                F::new(1214873956),
                F::new(258084305),
                F::new(2002146002),
                F::new(645480002),
                F::new(499722232),
                F::new(67463537),
                F::new(272555026),
                F::new(342163208),
            ],
        ],
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
        flags: vec![F::new(0), F::new(0)],
        leaf_is_right_child: F::new(0),
    };
    let proof = MerkleProof {
        root: [
            F::new(834733639),
            F::new(1317596101),
            F::new(525640951),
            F::new(1305261139),
            F::new(763682782),
            F::new(2096546268),
            F::new(278662),
            F::new(548463637),
        ],
        path: path,
    };
    return proof;
}
