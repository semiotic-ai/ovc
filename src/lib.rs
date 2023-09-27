use std::ops::Mul;
use ark_bn254::{G1Projective, Fr};

pub fn commit_unrolled(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (Vec<G1Projective>, G1Projective)
{
    let unrolled_commitment: Vec<G1Projective> = commit_key.iter().zip(hashed_logs_vec).map(|(g, l)| g.mul(l)).collect();
    let commitment = unrolled_commitment.iter().sum();

    (unrolled_commitment, commitment)
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

}
