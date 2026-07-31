#![allow(dead_code)]

mod generators;
mod hash;
mod issuance;
mod mint;
mod spend;

use bitcoin_hashes::sha256;
use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;

use crate::hash::{hash_to_g1, map_to_scalar};
use crate::issuance::{
    compute_c_m, get_challenge_issuance, issuance_homomorphism, prepare_issuance, IssuanceProof,
};
use crate::mint::{
    AggregatePublicKey, BatchedIssuance, ECash, PublicKeyShare, Signature, SignatureShare, Spend,
};
use crate::spend::prepare_spend;

#[derive(Copy, Clone)]
pub struct IssuanceRequest {
    m_1: Scalar,
    m_2: Scalar,
    m_3: Scalar,
    r_p: Scalar,
    r_m: Scalar,
    r_1: Scalar,
    r_2: Scalar,
    r_3: Scalar,
}
pub struct BatchedIssuanceRequest {
    requests: Vec<IssuanceRequest>,
    batched_y: Vec<[G1Projective; 5]>,
    h: G1Projective,
}
pub struct SpendRequest {
    e_cash: ECash,
    re_blinding: [Scalar; 2],
}

impl IssuanceRequest {
    pub fn new(amount: u64, authentication: sha256::Hash, r_p: Scalar) -> Self {
        let m_1 = Scalar::from(amount);
        let m_2 = Scalar::random(&mut thread_rng());
        let m_3 = map_to_scalar(&authentication);

        let r_m = Scalar::random(&mut thread_rng());
        let r_1 = Scalar::random(&mut thread_rng());
        let r_2 = Scalar::random(&mut thread_rng());
        let r_3 = Scalar::random(&mut thread_rng());

        IssuanceRequest {
            m_1,
            m_2,
            m_3,
            r_p,
            r_m,
            r_1,
            r_2,
            r_3,
        }
    }

    pub fn verify_blind_signature_share(
        &self,
        pk: &PublicKeyShare,
        h: &G1Projective,
        signature: &SignatureShare,
    ) -> bool {
        self.verify_signature(&pk.g2, h, &self.unblind_signature(&pk.g1, &signature.0))
    }

    pub fn verify_blind_signature(&self, pk: &AggregatePublicKey, signature: &Signature) -> bool {
        self.verify_signature(
            &pk.g2,
            &signature.h,
            &self.unblind_signature(&pk.g1, &signature.sigma),
        )
    }

    fn unblind_signature(&self, g1: &[G1Projective; 4], signature: &G1Projective) -> G1Projective {
        signature - self.blinding_factor(g1)
    }

    fn compute_message(&self, pk: &[G2Projective; 4]) -> G2Projective {
        pk[0] + self.m_1 * pk[1] + self.m_2 * pk[2] + self.m_3 * pk[3]
    }

    fn verify_pairing(&self, message: G2Projective, h: G1Projective, s: G1Projective) -> bool {
        let p_m = pairing(&h.to_affine(), &message.to_affine());
        let p_s = pairing(&s.to_affine(), &generators::ecash_g2().to_affine());

        p_m == p_s
    }

    fn verify_signature(
        &self,
        g2: &[G2Projective; 4],
        h: &G1Projective,
        signature: &G1Projective,
    ) -> bool {
        let message = self.compute_message(g2);

        self.verify_pairing(message, *h, *signature)
    }

    fn blinding_factor(&self, pk: &[G1Projective; 4]) -> G1Projective {
        self.r_1 * pk[1] + self.r_2 * pk[2] + self.r_3 * pk[3]
    }

    pub fn finalize_issuance(
        &self,
        pk: &AggregatePublicKey,
        signature: &Signature,
        auth: sha256::Hash,
    ) -> ECash {
        let unblinded_signature = self.unblind_signature(&pk.g1, &signature.sigma);

        assert!(self.verify_signature(&pk.g2, &signature.h, &unblinded_signature));
        assert!(self.m_3 == map_to_scalar(&auth));

        ECash {
            signature: Signature {
                h: signature.h,
                sigma: unblinded_signature,
            },
            value: self.m_1,
            serial: self.m_2,
            pedersen_rand: self.r_p,
            auth: auth,
        }
    }
}

impl BatchedIssuanceRequest {
    pub fn new(requests: &Vec<IssuanceRequest>) -> Self {
        let batched_c_m_bytes = requests.iter().fold(Vec::new(), |mut acc, requst| {
            let c_m = compute_c_m(requst.m_1, requst.m_2, requst.m_3, requst.r_m)
                .to_affine()
                .to_compressed();
            acc.extend_from_slice(c_m.as_slice());
            acc
        });
        BatchedIssuanceRequest {
            requests: requests.clone(),
            batched_y: Vec::new(),
            h: hash_to_g1(&batched_c_m_bytes),
        }
    }

    pub fn add_request(&mut self, request: &IssuanceRequest) {
        self.requests.push(request.clone());
    }

    pub fn prepare_batched_issuance(&mut self) -> BatchedIssuance {
        let mut r_proof: [G1Projective; 5] = std::array::from_fn(|_| G1Projective::identity());
        let mut batched_rho = Vec::new();
        let mut s_proof: [Scalar; 8] = std::array::from_fn(|_| Scalar::zero());
        self.batched_y = self
            .requests
            .iter()
            .map(|item| {
                prepare_issuance(
                    item.m_1, item.m_2, item.m_3, item.r_p, item.r_m, item.r_1, item.r_2, item.r_3,
                    self.h,
                )
            })
            .collect::<Vec<[G1Projective; 5]>>();
        for _ in &self.requests {
            let (r_proof_request, rho_request) = issuance_homomorphism(None, self.h);
            batched_rho.push(rho_request);
            for (point, new_point) in r_proof.iter_mut().zip(r_proof_request.iter()) {
                *point += *new_point;
            }
        }
        for index in 0..self.requests.len() {
            let challenge_request = get_challenge_issuance(&self.batched_y, &r_proof, index);
            let rho = batched_rho[index];
            s_proof[0] += rho[0] + challenge_request * self.requests[index].m_1;
            s_proof[1] += rho[1] + challenge_request * self.requests[index].m_2;
            s_proof[2] += rho[2] + challenge_request * self.requests[index].m_3;
            s_proof[3] += rho[3] + challenge_request * self.requests[index].r_p;
            s_proof[4] += rho[4] + challenge_request * self.requests[index].r_m;
            s_proof[5] += rho[5] + challenge_request * self.requests[index].r_1;
            s_proof[6] += rho[6] + challenge_request * self.requests[index].r_2;
            s_proof[7] += rho[7] + challenge_request * self.requests[index].r_3;
        }
        BatchedIssuance {
            batched_y: self.batched_y.clone(),
            proof: IssuanceProof {
                r: r_proof,
                s: s_proof,
            },
        }
    }
}

impl SpendRequest {
    fn new(e_cash: &ECash) -> Self {
        let rand = Scalar::random(&mut thread_rng());
        let rand_prime = Scalar::random(&mut thread_rng());
        let blinded_signature = Signature {
            sigma: e_cash.signature.sigma * rand + e_cash.signature.h * rand * rand_prime,
            h: e_cash.signature.h * rand,
        };
        let blinded_e_cash = ECash {
            signature: blinded_signature,
            ..*e_cash
        };
        assert!(blinded_e_cash.signature.h == e_cash.signature.h * rand);
        SpendRequest {
            e_cash: blinded_e_cash,
            re_blinding: [rand, rand_prime],
        }
    }
    pub fn prepare_spend(self, pk: [G2Projective; 4]) -> Spend {
        let ((p, k), proof) = prepare_spend(
            self.e_cash.value,
            self.e_cash.serial,
            self.e_cash.pedersen_rand,
            pk,
        );
        Spend {
            p: p,
            k: k,
            signature: self.e_cash.signature,
            v: generators::ecash_g2() * self.re_blinding[1],
            proof: proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::sha256;
    use bls12_381::Scalar;
    use ff::Field;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    use crate::{
        issuance::aggregate_signature_shares,
        mint::{mint_keygen, SignatureShare},
        BatchedIssuanceRequest, IssuanceRequest, SpendRequest,
    };

    #[test]
    fn test_issuance_request() {
        let blinding_sk = Scalar::random(&mut thread_rng());
        let amount = 1000;
        let first_request = IssuanceRequest::new(amount, sha256::Hash::hash(&[0; 32]), blinding_sk);
        let second_request =
            IssuanceRequest::new(amount, sha256::Hash::hash(&[0; 32]), blinding_sk);
        let mut batched_request = BatchedIssuanceRequest::new(&vec![first_request, second_request]);

        let batched_issuance = batched_request.prepare_batched_issuance();

        assert!(batched_issuance.verify());
    }
    #[test]
    fn test_e_cash_generation() {
        let blinding_sk = Scalar::random(&mut thread_rng());
        let amount = 1000;
        let auth = sha256::Hash::hash(&[0; 32]);
        let request_index = 1;
        let first_request = IssuanceRequest::new(amount, auth, blinding_sk);
        let second_request =
            IssuanceRequest::new(amount, sha256::Hash::hash(&[0; 32]), blinding_sk);
        let mut batched_request = BatchedIssuanceRequest::new(&vec![first_request, second_request]);

        let batched_issuance = batched_request.prepare_batched_issuance();
        let (agg_pub_keys, pub_keys, sec_keys) = mint_keygen(5, 7);
        let signature_shares = sec_keys
            .iter()
            .map(|sk| batched_issuance.sign(sk)[request_index].clone())
            .collect::<Vec<SignatureShare>>();
        for (pk, share) in pub_keys.iter().zip(signature_shares.iter()) {
            assert!(
                batched_request.requests[request_index].verify_blind_signature_share(
                    pk,
                    &batched_request.h,
                    &share
                )
            );
        }

        let signature_shares = (1_u64..)
            .zip(signature_shares)
            .take(5)
            .collect::<BTreeMap<u64, SignatureShare>>();

        let signature = aggregate_signature_shares(batched_request.h, &signature_shares);

        assert!(batched_request.requests[request_index]
            .verify_blind_signature(&agg_pub_keys, &signature));

        let _e_cash_note = batched_request.requests[request_index].finalize_issuance(
            &agg_pub_keys,
            &signature,
            auth,
        );
    }
    #[test]
    fn test_spend() {
        let blinding_sk = Scalar::random(&mut thread_rng());
        let amount = 1000;
        let auth = sha256::Hash::hash(&[0; 32]);
        let request_index = 1;
        let first_request = IssuanceRequest::new(amount, auth, blinding_sk);
        let second_request =
            IssuanceRequest::new(amount, sha256::Hash::hash(&[0; 32]), blinding_sk);
        let mut batched_request = BatchedIssuanceRequest::new(&vec![first_request, second_request]);

        let batched_issuance = batched_request.prepare_batched_issuance();
        let (agg_pub_keys, pub_keys, sec_keys) = mint_keygen(5, 7);
        let signature_shares = sec_keys
            .iter()
            .map(|sk| batched_issuance.sign(sk)[request_index].clone())
            .collect::<Vec<SignatureShare>>();
        for (pk, share) in pub_keys.iter().zip(signature_shares.iter()) {
            assert!(
                batched_request.requests[request_index].verify_blind_signature_share(
                    pk,
                    &batched_request.h,
                    &share
                )
            );
        }

        let signature_shares = (1_u64..)
            .zip(signature_shares)
            .take(5)
            .collect::<BTreeMap<u64, SignatureShare>>();

        let signature = aggregate_signature_shares(batched_request.h, &signature_shares);

        assert!(batched_request.requests[request_index]
            .verify_blind_signature(&agg_pub_keys, &signature));

        let e_cash_note = batched_request.requests[request_index].finalize_issuance(
            &agg_pub_keys,
            &signature,
            auth,
        );
        let spend_request = SpendRequest::new(&e_cash_note);
        let spend = spend_request.prepare_spend(agg_pub_keys.g2);
        assert!(spend.verify(agg_pub_keys, auth));
    }
}
