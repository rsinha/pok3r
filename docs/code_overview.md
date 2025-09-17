# Insta-Pok3r Code Overview

This document summarizes the structure and behaviour of the Rust code in the Insta-Pok3r repository. The project implements a multi-party computation (MPC) protocol for shuffling, encrypting and revealing a deck of cards with accompanying zero-knowledge proofs. The high-level workflow combines libp2p-based gossip networking, SPDZ-style secret sharing, KZG polynomial commitments, and an identity-based encryption (IBE) scheme over the BLS12-377 pairing-friendly curve.

## Execution Flow

The binary entry point in `src/main.rs` parses the peer identifier, deterministic seed and party count from the command line using `clap` before coordinating two long-lived tasks: a networking daemon and the MPC evaluator.【F:src/main.rs†L1-L120】 The networking daemon runs in a separate thread so that asynchronous libp2p processing does not block MPC logic. Communication between the two tasks uses unbounded channels carrying `EvalNetMsg` enums that encode both single-value and batched secret-share broadcasts.【F:src/main.rs†L121-L214】【F:src/common.rs†L16-L42】 After instantiating `MessagingSystem` and `Evaluator`, the main routine performs the protocol in sequence:

1. Generate public parameters for KZG commitments (`compute_params`).【F:src/main.rs†L215-L224】【F:src/shuffler.rs†L15-L26】
2. Sample a placeholder master secret/public key pair for the IBE-based encryption layer (`compute_keyper_keys`).【F:src/main.rs†L225-L232】【F:src/shuffler.rs†L28-L37】
3. Produce MPC shares representing a shuffled deck (`shuffle_deck`).【F:src/main.rs†L234-L240】【F:src/shuffler.rs†L49-L117】
4. Build and prove a permutation argument for the committed deck (`compute_permutation_argument`).【F:src/main.rs†L241-L252】【F:src/shuffler.rs†L119-L393】
5. Encrypt every card share and prove correctness of the encryption (`encrypt_and_prove`).【F:src/main.rs†L254-L275】【F:src/shuffler.rs†L405-L733】
6. Derive deterministic card identifiers, decrypt the ciphertexts with the shared master secret, and verify both permutation and encryption proofs before asserting the recovered deck is a valid permutation.【F:src/main.rs†L276-L318】

The `run.sh` helper script demonstrates how to spawn multiple deterministic peers by choosing seeds and peer IDs, then tails log output for monitoring.【F:run.sh†L1-L38】

## Networking Layer

`src/network.rs` provides the messaging substrate that connects the MPC evaluator to other peers. `run_networking_daemon` builds a libp2p swarm that multiplexes QUIC or TCP transports secured with Noise, participates in a Gossipsub overlay, and discovers peers via mDNS.【F:src/network.rs†L1-L121】 Messages emitted by the evaluator are serialized into JSON `EvalNetMsg` variants and published on a shared topic; inbound gossip messages are forwarded back to the evaluator thread through the control channel.【F:src/network.rs†L70-L144】 The daemon also monitors peer discovery events and signals the evaluator once all known peers from the address book are connected.【F:src/network.rs†L108-L143】

`MessagingSystem` wraps the channels exposed by the daemon. It tracks messages per wire handle in an in-memory mailbox so that batched gossip publications can be matched to the expected senders.【F:src/network.rs†L146-L259】 The `send_to_all` method emits either single-value or batched publish messages, while `recv_from_all` blocks until it has collected shares from every other peer for a given identifier before returning a map keyed by numeric node IDs.【F:src/network.rs†L188-L236】 Helper methods convert peer IDs to numeric indices using the address book defined in `src/address_book.rs`.【F:src/address_book.rs†L1-L25】

## MPC Evaluator

The `Evaluator` struct encapsulates the SPDZ-like arithmetic used throughout the protocol.【F:src/evaluator.rs†L1-L109】 It maintains maps of wire handles to field shares, consumes preprocessed Beaver triples and random sharings, and stores counters to guarantee unique labels. The `new` constructor requests large batches of triples and random sharings during start-up to amortize preprocessing costs.【F:src/evaluator.rs†L19-L65】【F:src/evaluator.rs†L824-L906】

### Wire Management and Local Arithmetic

Every MPC value is referenced by a base58-encoded wire handle derived from a monotonically increasing gate counter.【F:src/evaluator.rs†L67-L94】 The evaluator offers helper gates for addition, subtraction, and scaling against clear scalars.【F:src/evaluator.rs†L96-L159】 `fixed_wire_handle` injects public constants into the circuit by giving the first party the full value and all others zero; `clear_add` performs an analogous adjustment on an existing secret share.【F:src/evaluator.rs†L160-L209】

### Multiplication and Inversion

Secret multiplications rely on preprocessed Beaver triples accessed via `beaver` or `batch_beaver`. The multiplication protocol reconstructs masked inputs `(x+a)` and `(y+b)` in the clear and adjusts with locally held triple shares to obtain `[xy]` while only the first party adds the constant cross term.【F:src/evaluator.rs†L210-L311】 `batch_mult` vectorizes this workflow to minimize network round-trips when evaluating polynomials or exponentiation circuits.【F:src/evaluator.rs†L313-L392】 The `batch_inv` routine converts additive shares of `s` into shares of `1/s` by multiplying with random masks, reconstructing the masked product and scaling the masks accordingly.【F:src/evaluator.rs†L111-L159】 `batch_exp` reuses repeated squaring through `batch_mult` to raise secret elements to the `(2^LOG_PERM_SIZE)` power required when sampling deck elements.【F:src/evaluator.rs†L593-L629】

### Polynomial Operations and Commitments

Polynomial evaluation and multiplication happen entirely on secret shares. `share_poly_eval` evaluates a locally held share of a polynomial at a clear point, while `share_poly_mult` evaluates both inputs on a larger multiplicative subgroup, multiplies pointwise via Beaver triples, and interpolates to obtain the product polynomial shares.【F:src/evaluator.rs†L394-L493】 These utilities underpin KZG commitment proofs built later in the protocol. The evaluator also constructs KZG opening proofs by dividing secret polynomials by `(X - z)` and committing to the quotient in the exponent.【F:src/evaluator.rs†L631-L705】

### Reconstruction and Exponentiation

To reveal values, the evaluator broadcasts local shares encoded in base58 and sums received contributions. `batch_output_wire` aggregates multiple wires efficiently by batching gossip publications before iterating through awaited responses.【F:src/evaluator.rs†L494-L573】 Similar helpers exist for reconstructing group elements: `batch_output_wire_in_exponent` collects `g^{share}` contributions, while `add_g1_elements_from_all_parties` and its `G2`/`Gt` variants add up masked exponentiations from every peer.【F:src/evaluator.rs†L575-L692】 Higher-level routines such as `exp_and_reveal_g1` or `batch_exp_and_reveal_gt` implement multi-scalar multiplications where the bases are public but scalars remain secret-shared until the sum is reconstructed.【F:src/evaluator.rs†L694-L791】

### Preprocessing

Random sharings are produced using Shamir secret sharing with threshold equal to the party count; each peer takes the share indexed by its numeric ID.【F:src/evaluator.rs†L806-L848】 Beaver triples are generated deterministically using a shared PRG so that all parties derive consistent correlated randomness without interaction.【F:src/evaluator.rs†L848-L906】

## Shuffling and Proof Generation

`src/shuffler.rs` contains the MPC-friendly deck shuffle and the zero-knowledge arguments that tie everything together. Parameters such as permutation size, deck size, and sampling counts come from `src/common.rs` and can be tuned for experiments.【F:src/common.rs†L5-L15】

### Deck Generation

`shuffle_deck` samples a random secret key share `[sk]`, then iteratively generates candidate card shares using random field elements. It computes PRFs of the form `g^{1/(sk + ω_i)}` over a multiplicative subgroup to ensure uniqueness, seeding the first `(PERM_SIZE - DECK_SIZE)` slots with fixed padding cards so that the final shuffled vector has length `PERM_SIZE`.【F:src/shuffler.rs†L49-L117】 Random cards are collected in batches via `batch_ran_64`, inverted with `batch_inv`, and deduplicated using a hash set of observed PRFs before returning the wire handles for all positions.【F:src/shuffler.rs†L71-L117】

### Permutation Argument

`compute_permutation_argument` constructs a batched permutation proof modeled after Plonk-style copy constraints. The function:

1. Samples random masks `r_i` and defines blinding scalars `b_i = r_i / r_0` using MPC inversion and multiplication helpers.【F:src/shuffler.rs†L119-L156】
2. Interpolates the shuffled deck shares into a polynomial `f(X)` over the multiplicative subgroup and commits to it using KZG, adding hiding terms proportional to `(X^{PERM_SIZE} - 1)` for zero-knowledge.【F:src/shuffler.rs†L157-L210】
3. Forms a shifted polynomial `g(X) = f(X) + y_1` where `y_1` is derived from a Fiat–Shamir hash of the commitments, and computes auxiliary sequences `s'_i`, `t'_i`, and cumulative products `t_i` that encode permutation constraints.【F:src/shuffler.rs†L211-L292】
4. Interpolates `t(X)` from the `t_i`, divides by `X/ω`, and combines it with `g(X)` and a public polynomial `h(X)` to obtain a quotient `q(X)` whose evaluation enforces the permutation relation.【F:src/shuffler.rs†L293-L358】
5. Produces KZG commitments and evaluation proofs for `t`, `g`, and `q` at carefully chosen challenge points (`w^{63}`, `y_2`, `y_2/ω`) while adjusting for hiding polynomials; the resulting values form the `PermutationProof` struct returned to the caller.【F:src/shuffler.rs†L360-L393】

`verify_permutation_argument` recomputes the deterministic challenges, verifies each KZG opening, and checks algebraic relations showing that the committed vector is a permutation of the canonical deck.【F:src/shuffler.rs†L395-L473】 The verifier also ensures that the cumulative product at the final root of unity equals one, preventing cycles shorter than the permutation size.【F:src/shuffler.rs†L474-L515】

### Encryption Argument

`encrypt_and_prove` uses an IBE-like construction to encrypt the shuffled cards to per-position identifiers using a shared public key. The evaluator samples a common randomness `[r]`, applies distributed exponentiation to compute `(g^r, e_i^{r})` pairs, and hashes all ciphertext elements plus a masking ciphertext tied to `alpha1` to derive a batching challenge `δ`.【F:src/shuffler.rs†L405-L521】 The same delta point is used to evaluate the card commitment polynomial and produce a KZG opening proof adjusted for the hiding term.【F:src/shuffler.rs†L522-L585】 The function then aggregates IBE bases weighted by Lagrange coefficients to compute `e_batch`, raises it to `[r]` inside MPC, and conducts a Schnorr-like sigma protocol showing consistency between `c1`, `t`, and the masked exponentiations.【F:src/shuffler.rs†L586-L733】 The resulting `EncryptionProof` records ciphertexts, evaluation proofs, and sigma transcript data.

`verify_encryption_argument` mirrors these steps in the clear: it recomputes `δ`, validates the KZG opening, checks that the aggregated ciphertexts match the commitment evaluation plus the MPC-produced `t`, and verifies the sigma protocol equations.【F:src/shuffler.rs†L735-L812】 Finally, `decrypt_one_card` demonstrates IBE decryption by pairing the ciphertext with a derived decryption key and comparing against a precomputed cache of `g^{ω_i}` values.【F:src/shuffler.rs†L814-L848】 Supporting helpers generate decryption keys and caches from the shared master secret.【F:src/shuffler.rs†L28-L47】

## Cryptographic and Utility Components

- `src/kzg.rs` implements the required subset of the KZG10 polynomial commitment scheme: setup, commitment, evaluation proof generation, and verification over a generic pairing-friendly curve.【F:src/kzg.rs†L1-L126】
- `src/shamir.rs` supplies Shamir secret sharing routines for distributing random scalars and reconstructing them when needed.【F:src/shamir.rs†L1-L79】
- `src/encoding.rs` serializes field and group elements to base58 strings for transport over the gossip network.【F:src/encoding.rs†L1-L33】
- `src/utils.rs` collects reusable primitives such as multiplicative subgroup generators, vanishing polynomials, Fiat–Shamir hashing, Lagrange interpolation, and polynomial transformations used throughout the shuffle and proof code.【F:src/utils.rs†L1-L120】
- `src/common.rs` defines global parameters (permutation size, deck size, preprocessing counts) and shared data structures like `EvalNetMsg`, `PermutationProof`, and `EncryptionProof`.【F:src/common.rs†L1-L43】

Together, these components form an end-to-end demonstration of a distributed poker shuffle with publicly verifiable proofs of correct permutation and encryption, built on top of asynchronous gossip networking and MPC-friendly cryptographic building blocks.
