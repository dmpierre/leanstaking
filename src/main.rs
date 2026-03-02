use lean_compiler::*;
use lean_vm::*;

pub mod data;
use data::two_levels_merkle_proof;

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
    nullifier: [F; 8],
    secret: [F; 8],
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
        res.extend_from_slice(&self.root);
        res
    }
}

impl Into<Vec<F>> for StakeProof {
    fn into(self) -> Vec<F> {
        let mut res = vec![];
        res.extend_from_slice(&self.nullifier);
        res.extend_from_slice(&self.secret);
        let merkle_proof: Vec<F> = self.merkle_proof.into();
        res.extend_from_slice(&merkle_proof);
        res
    }
}

fn main() {
    let path = format!("{}/py/stake.py", env!("CARGO_MANIFEST_DIR"));
    let lean_pg = &ProgramSource::Filepath(path);
    let merkle_proof = two_levels_merkle_proof();
    let stake_proof = StakeProof {
        nullifier: [F::new(2); 8],
        secret: [F::new(7); 8],
        merkle_proof,
    };
    let public_inputs: Vec<F> = stake_proof.into();
    compile_and_run(lean_pg, (&public_inputs, &[]), false);
}

#[cfg(test)]
pub mod tests {

    use lean_compiler::*;
    use lean_vm::*;

    #[test]
    pub fn test_commit() {
        let path = format!("{}/py/commit.py", env!("CARGO_MANIFEST_DIR"));
        let lean_pg = &ProgramSource::Filepath(path);
        let nullifier = [F::new(23); 8];
        let secret = [F::new(29); 8];
        let a_b = [secret, nullifier].concat();
        compile_and_run(lean_pg, (&a_b, &[]), false);
    }

    #[test]
    pub fn test_hash() {
        let a = [
            F::new(760229910),
            F::new(1609661003),
            F::new(814780643),
            F::new(2041690851),
            F::new(1904291566),
            F::new(1778725946),
            F::new(987198971),
            F::new(1396432968),
        ];
        let b = [
            F::new(300284318),
            F::new(184251726),
            F::new(785324177),
            F::new(1645200318),
            F::new(218255519),
            F::new(324974344),
            F::new(38180562),
            F::new(1122512566),
        ];
        let path = format!("{}/py/hash.py", env!("CARGO_MANIFEST_DIR"));
        let lean_pg = &ProgramSource::Filepath(path);
        let a_b = [a, b].concat();
        compile_and_run(lean_pg, (&a_b, &[]), false);
    }
}
