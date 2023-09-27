use std::ops::Mul;
use ark_bn254::{G1Projective, Fr};
use ark_crypto_primitives::{merkle_tree::{self, ByteDigestConverter, MerkleTree, Config}, crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme}};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
pub fn commit_unrolled(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (Vec<G1Projective>, G1Projective)
{
    let unrolled_commitment: Vec<G1Projective> = commit_key.iter().zip(hashed_logs_vec).map(|(g, l)| g.mul(l)).collect();
    let commitment = unrolled_commitment.iter().sum();

    (unrolled_commitment, commitment)
}


type LeafH = Sha256;
type CompressH = Sha256;

struct Sha256MerkleTreeParams;

impl Config for Sha256MerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}
type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;

pub fn commit_and_merkle(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (G1Projective, Sha256MerkleTree)
{
    let (unrolled_commitment, commitment) = commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());
    let mut unrolled_commitment_serialized= Vec::new();
    for uc in unrolled_commitment.iter() {
        let mut compressed_bytes = Vec::new();
        uc.serialize_compressed(&mut compressed_bytes).unwrap();
        unrolled_commitment_serialized.push(compressed_bytes);
    }
    let merkle_tree = Sha256MerkleTree::new(&(), &(), unrolled_commitment_serialized.clone()).unwrap();

    (commitment, merkle_tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{VariableBaseMSM, CurveGroup};
    use ark_std::{self, UniformRand};
    use ark_bn254::G1Projective as G;
    

    // Test commit_unrolled
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_unrolled(){
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..10 {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Generate random vector of Fr
        let mut hashed_logs_vec: Vec<Fr> = Vec::new();
        for _ in 0..10 {
            hashed_logs_vec.push(Fr::rand(&mut rng));
        }

        // Compute unrolled commitment
        let (unrolled_commitment, commitment) = commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());

        // Check length of unrolled commitment
        assert_eq!(unrolled_commitment.len(), 10);

        // Check that commitment equals expected value
        let commit_key_affine = commit_key.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let expected_commitment = G::msm(commit_key_affine.as_slice(), hashed_logs_vec.as_slice()).unwrap();
        assert_eq!(commitment.into_affine(), expected_commitment);

        // Check that unrolled commitment values are as expected
        let expected_commitment_5 =  commit_key[5].mul(hashed_logs_vec[5]); 
        assert_eq!(unrolled_commitment[5], expected_commitment_5);
    }

    // Test commit_and_merkle
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_and_merkle(){
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..8 {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Generate random vector of Fr
        let mut hashed_logs_vec: Vec<Fr> = Vec::new();
        for _ in 0..8 {
            hashed_logs_vec.push(Fr::rand(&mut rng));
        }

        // Compute Merkle tree
        let (_commitment, merkle_tree) = commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

        // Check inclusion proof
        let mut test_bytes = Vec::new();
        commit_key[5].mul(hashed_logs_vec[5]).serialize_compressed(&mut test_bytes).unwrap();
        let inclusion_proof = merkle_tree.generate_proof(5).unwrap();
        let root = merkle_tree.root();
        assert!(inclusion_proof.verify(&(), &(), &root, test_bytes).unwrap());

    }

}
