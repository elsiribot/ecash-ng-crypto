use bitcoin_hashes::sha256;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use rand::thread_rng;
use std::{array};

use crate::generators;
use crate::hash::hash_g1_to_g1;
use crate::issuance::{compute_batched_h, verify_batched_issuance, verify_issuance, IssuanceProof};

pub struct AggregatePublicKey {
    pub g1: [G1Projective; 4],
    pub g2: [G2Projective; 4],
}

pub struct PublicKeyShare {
    pub g1: [G1Projective; 4],
    pub g2: [G2Projective; 4],
}

pub struct Issuance {
    pub y: [G1Projective; 5],
    pub r: [G1Projective; 5],
    pub s: [Scalar; 8],
}

pub struct BatchedIssuance {
    pub batched_y: Vec<[G1Projective; 5]>,
    pub proof: IssuanceProof,
}
#[derive(Clone, Copy)]
pub struct SignatureShare(pub G1Projective);

pub struct Signature {
    pub h: G1Projective,
    pub sigma: G1Projective,
}
pub struct SecretKeyShare([Scalar; 4]);

pub struct ECash {
    pub signature: Signature,
    pub value: Scalar,
    pub serial: Scalar,
    pub auth: sha256::Hash
}

pub fn mint_keygen(
    threshold: usize,
    keys: usize,
) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
    let polys: [Vec<Scalar>; 4] = array::from_fn(|_| random_polynomial(threshold));

    let g1 = polys
        .clone()
        .map(|p| generators::ecash_g1() * evaluate(&p, &Scalar::zero()));

    let g2 = polys
        .clone()
        .map(|p| generators::ecash_g2() * evaluate(&p, &Scalar::zero()));

    let apk = AggregatePublicKey { g1, g2 };

    let sks = (0..keys)
        .map(|idx| {
            SecretKeyShare(
                polys
                    .clone()
                    .map(|p| evaluate(&p, &Scalar::from(idx as u64 + 1))),
            )
        })
        .collect::<Vec<SecretKeyShare>>();

    let pks = sks
        .iter()
        .map(|sk| PublicKeyShare {
            g1: sk.0.map(|s| generators::ecash_g1() * s),
            g2: sk.0.map(|s| generators::ecash_g2() * s),
        })
        .collect::<Vec<PublicKeyShare>>();

    (apk, pks, sks)
}

fn random_polynomial(degree: usize) -> Vec<Scalar> {
    (0..degree)
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect()
}

fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .cloned()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
}

impl Issuance {
    pub fn verify(&self) -> bool {
        verify_issuance(self.y, self.r, self.s)
    }

    pub fn sign(&self, secret_key: &SecretKeyShare) -> SignatureShare {
        let h = hash_g1_to_g1(self.y[1]);

        SignatureShare(sign_blinded_message(
            secret_key.0,
            h,
            self.y[2],
            self.y[3],
            self.y[4],
        ))
    }
}

impl BatchedIssuance {
    pub fn verify(&self) -> bool {
        verify_batched_issuance(&self.batched_y, &self.proof)
    }

    pub fn sign(&self, secret_key: &SecretKeyShare) -> Vec<SignatureShare> {
        let mut signature_shares = Vec::new();
        let h: G1Projective = compute_batched_h(&self.batched_y);
        for y in &self.batched_y {
            signature_shares.push(SignatureShare(sign_blinded_message(
                secret_key.0,
                h,
                y[2],
                y[3],
                y[4],
            )));
        }
        signature_shares
    }
}

fn sign_blinded_message(
    sk: [Scalar; 4],
    h: G1Projective,
    c_1: G1Projective,
    c_2: G1Projective,
    c_3: G1Projective,
) -> G1Projective {
    sk[0] * h + sk[1] * c_1 + sk[2] * c_2 + sk[3] * c_3
}
