use crate::hash::hash_to_g1;
use bitcoin_hashes::sha256;
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::thread_rng;
use std::array;
use std::io::Write;

pub struct IssuanceProof {
    pub r: [G1Projective; 5],
    pub s: [Scalar; 8],
}

pub fn issuance_homomorphism(
    rho: Option<[Scalar; 8]>,
    h: G1Projective,
) -> ([G1Projective; 5], [Scalar; 8]) {
    let rho = rho.unwrap_or(array::from_fn(|_| Scalar::random(&mut thread_rng())));
    let pc = crate::compute_pc(rho[0], rho[3]);
    let c_m = compute_c_m(rho[0], rho[1], rho[2], rho[4]);
    let c_1 = compute_c_k(rho[0], rho[5], h);
    let c_2 = compute_c_k(rho[1], rho[6], h);
    let c_3 = compute_c_k(rho[2], rho[7], h);

    ([pc, c_m, c_1, c_2, c_3], rho)
}

pub fn compute_c_m(m_1: Scalar, m_2: Scalar, m_3: Scalar, r_m: Scalar) -> G1Projective {
    m_1 * crate::generators::ecash_h1()
        + m_2 * crate::generators::ecash_h2()
        + m_3 * crate::generators::ecash_h3()
        + r_m * crate::generators::ecash_g1()
}

pub fn compute_c_k(m: Scalar, r: Scalar, h: G1Projective) -> G1Projective {
    m * h + r * crate::generators::ecash_g1()
}

pub fn prove_issuance(y: [G1Projective; 5], x: [Scalar; 8], h: G1Projective) -> IssuanceProof {
    let r = array::from_fn(|_| Scalar::random(&mut thread_rng()));
    let (r_proof, _) = issuance_homomorphism(Some(r), h);

    let challenge = get_challenge_issuance(&vec![y], &r_proof, 0_usize);

    let s_proof = array::from_fn(|i| r[i] + challenge * x[i]);

    assert!(verify_issuance(y, r_proof, s_proof));

    IssuanceProof {
        r: r_proof,
        s: s_proof,
    }
}

pub fn verify_issuance(y: [G1Projective; 5], r: [G1Projective; 5], s: [Scalar; 8]) -> bool {
    let h = crate::hash::hash_g1_to_g1(y[1]);
    let challenge = get_challenge_issuance(&vec![y], &r, 0_usize);

    let (r_proof, _) = issuance_homomorphism(Some(s), h);
    r_proof == array::from_fn(|i| challenge * y[i] + r[i])
}

pub fn get_challenge_issuance(
    y: &Vec<[G1Projective; 5]>,
    r: &[G1Projective; 5],
    index: usize,
) -> Scalar {
    let mut engine = sha256::HashEngine::default();

    engine
        .write_all("FEDIMINT_ECASH_CHALLENGE_ISSUANCE".as_bytes())
        .expect("Writing to hash engine can't fail");

    for instance in y {
        for point in instance {
            engine
                .write_all(&point.to_affine().to_compressed())
                .expect("Writing to hash engine can't fail");
        }
    }

    for point in r {
        engine
            .write_all(&point.to_affine().to_compressed())
            .expect("Writing to hash engine can't fail");
    }
    engine
        .write_all(&index.to_be_bytes())
        .expect("Writing the index to the engine failed");

    let hash = sha256::Hash::from_engine(engine);

    crate::hash::map_to_scalar(&hash)
}

pub fn prepare_issuance(
    m_1: Scalar,
    m_2: Scalar,
    m_3: Scalar,
    r_p: Scalar,
    r_m: Scalar,
    r_1: Scalar,
    r_2: Scalar,
    r_3: Scalar,
    h: G1Projective,
) -> [G1Projective; 5] {
    let pc = crate::compute_pc(m_1, r_p);
    let c_m = compute_c_m(m_1, m_2, m_3, r_m);

    let c_1 = compute_c_k(m_1, r_1, h);
    let c_2 = compute_c_k(m_2, r_2, h);
    let c_3 = compute_c_k(m_3, r_3, h);

    [pc, c_m, c_1, c_2, c_3]
}

pub fn verify_batched_issuance(y: &Vec<[G1Projective; 5]>, proof: &IssuanceProof) -> bool {
    let mut rhs: [G1Projective; 5] = std::array::from_fn(|_| G1Projective::identity());
    let h = compute_batched_h(y);
    for index in 0..y.len() {
        let challenge_request = get_challenge_issuance(&y, &proof.r, index);
        for (point, new_point) in rhs.iter_mut().zip(y[index].iter()) {
            *point += *new_point * challenge_request;
        }
    }
    for (point, new_point) in rhs.iter_mut().zip(proof.r.iter()) {
        *point += *new_point;
    }

    let (r_proof, _) = issuance_homomorphism(Some(proof.s), h);
    r_proof == rhs
}

pub fn compute_batched_h(batched_y: &Vec<[G1Projective; 5]>) -> G1Projective {
    let batched_c_m_bytes = batched_y.iter().fold(Vec::new(), |mut acc, y| {
        let c_m = y[1].to_affine().to_compressed();
        acc.extend_from_slice(c_m.as_slice());
        acc
    });
    hash_to_g1(&batched_c_m_bytes)
}
