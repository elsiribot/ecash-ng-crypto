# ecash-ng-crypto

Prototype of a threshold confidential scheme for federated e-cash: Coconut-style
blind issuance of Pointcheval–Sanders signatures over BLS12-381, with three
hidden attributes per note (amount, serial secret, spend condition) and
unlinkable zero-knowledge spends.

**A full description of the scheme in mathematical notation is available in the docs folder.**

## Layout

- `src/lib.rs` — protocol flow: issuance request, batched issuance request, and spending request.
- `src/issuance.rs` — issuance commitments and Σ-proof
- `src/mint.rs` - mint functionalities: blind signing, spend/issaunce request verification.
- `src/spend.rs` — spend Σ-proof
- `src/generators.rs` — nothing-up-my-sleeve generators
- `src/hash.rs` — hash-to-group / hash-to-scalar helpers

## Usage

```bsh
cargo test    # roundtrip: issue 5-of-7 batching 2 issuance requests as well as testing the spending for a batched issuance for a single eCash
```

**Prototype Notice:** This repository contains unreviewed prototype code and **must not be used in production**.

This repository builds upon the upgraded version of [joschisan/ecash-ng-crypto](https://github.com/joschisan/ecash-ng-crypto), extending it with secure batching of zero-knowledge proofs for both spending and issuance. These enhancements are intended to make the eCash scheme practical by reducing the computational overhead of proof generation and verification.
