use lean_compiler::*;
use lean_vm::*;

pub mod data;

use crate::data::three_levels_merkle_proof;

pub struct MerklePath {
    pub leaf_sibling: [F; 8],
    pub auth_path: Vec<[F; 8]>,
    pub flags: Vec<F>,
    pub leaf_is_right_child: F,
}

pub struct MerkleProof {
    pub root: [F; 8],
    path: MerklePath,
}

pub struct StakeProof {
    nullifier_preimage: [F; 8],
    validator_key: [F; 13],
    withdrawal_cred: [F; 9],
    nullifier: [F; 8],
    amount: F,
    pub merkle_proof: MerkleProof,
}

impl Into<Vec<F>> for MerkleProof {
    fn into(self) -> Vec<F> {
        assert_eq!(self.path.flags.len(), self.path.auth_path.len());
        let mut res = vec![];
        res.extend_from_slice(&self.path.leaf_sibling);
        res.push(self.path.leaf_is_right_child);
        for (node, flag) in self.path.auth_path.iter().zip(self.path.flags) {
            res.extend_from_slice(node);
            res.push(flag);
        }
        res
    }
}

pub struct StakeProofInputs {
    pub public_inputs: Vec<F>,
    pub private_inputs: Vec<F>,
}

impl Into<StakeProofInputs> for StakeProof {
    fn into(self) -> StakeProofInputs {
        let mut public_inputs = vec![];
        let mut private_inputs = vec![];

        // public inputs
        public_inputs.extend_from_slice(&self.validator_key);
        public_inputs.extend_from_slice(&self.withdrawal_cred);
        public_inputs.push(self.amount);
        public_inputs.extend_from_slice(&self.nullifier);
        public_inputs.extend_from_slice(&self.merkle_proof.root);

        // private inputs
        private_inputs.extend_from_slice(&self.nullifier_preimage);
        let merkle_proof: Vec<F> = self.merkle_proof.into();
        private_inputs.extend_from_slice(&merkle_proof);

        StakeProofInputs {
            public_inputs,
            private_inputs,
        }
    }
}

fn main() {
    let path = format!("{}/py/stake.py", env!("CARGO_MANIFEST_DIR"));
    let lean_pg = &ProgramSource::Filepath(path);
    let merkle_proof = three_levels_merkle_proof();
    let nullifier = [
        F::new(1943526546),
        F::new(660031786),
        F::new(925555113),
        F::new(1029853471),
        F::new(791673069),
        F::new(822174872),
        F::new(578818453),
        F::new(1335880560),
    ];
    let stake_proof = StakeProof {
        nullifier_preimage: [F::new(2); 8],
        validator_key: [F::new(7); 13],
        withdrawal_cred: [F::new(3); 9],
        amount: F::new(32),
        merkle_proof,
        nullifier,
    };
    let inputs: StakeProofInputs = stake_proof.into();

    compile_and_run(
        lean_pg,
        (&inputs.public_inputs, &inputs.private_inputs),
        false,
    );
}

#[cfg(test)]
pub mod tests {

    use lean_compiler::*;
    use lean_vm::*;

    #[test]
    pub fn test_commit() {
        let path = format!("{}/py/commit.py", env!("CARGO_MANIFEST_DIR"));
        let lean_pg = &ProgramSource::Filepath(path);
        let nullifier_preimage = [F::new(23); 8];
        let validator_key = [F::new(29); 13];
        let withdrawal_cred = [F::new(31); 9];
        let amount = [F::new(32)];
        let inputs = [
            nullifier_preimage.as_slice(),
            validator_key.as_slice(),
            withdrawal_cred.as_slice(),
            amount.as_slice(),
        ]
        .concat();
        compile_and_run(lean_pg, (&inputs, &[]), false);
    }

    #[test]
    pub fn test_hash() {
        let a = [
            F::new(1214873956),
            F::new(258084305),
            F::new(2002146002),
            F::new(645480002),
            F::new(499722232),
            F::new(67463537),
            F::new(272555026),
            F::new(342163208),
        ];
        let b = a.clone();
        let path = format!("{}/py/hash.py", env!("CARGO_MANIFEST_DIR"));
        let lean_pg = &ProgramSource::Filepath(path);
        let a_b = [a, b].concat();
        compile_and_run(lean_pg, (&a_b, &[]), false);
    }
}
