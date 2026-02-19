# CLAUDE.md — proofs/

## What this directory is

Formal mathematical proofs supporting the correctness of the XMSS/XMSS-MT
implementations in `impl/`. Currently contains one document:

- `treehash-equivalence.md` — proof of the equivalence of the
  iterative and recursive definitions of the XMSS Merkle tree, for both
  XMSS and XMSS-MT. **Status: draft — all proof bodies filled in;
  under review.**

The goal is eventually to mechanise these proofs in EasyCrypt, but the
immediate task is a clean, self-contained mathematical document. Do not
worry about EasyCrypt syntax or proof strategy yet; focus on getting the
mathematical arguments right first.

## How this document came to exist

The proof obligations were developed through a design conversation. The
key insights reached in that conversation are summarised below — do not
re-derive them from scratch, but do scrutinise them carefully.

## Mathematical context you must internalise

### The core tension

RFC 8391 Algorithm 9 (treeHash) is defined *iteratively* using a stack.
Security proofs need a *recursive* definition:

  Tree(0, i)    = leaf(i)
  Tree(h, s)    = H(addr(ℓ,τ,h, s/2^h), Tree(h-1,s), Tree(h-1, s+2^{h-1}))

Proving these equivalent is the task. The difficulty is not the values —
it is the *addresses*. The hash H takes an address as input for domain
separation. The proof must show every hash call in the iterative algorithm
uses exactly the address the recursive definition would use. Value
correctness and address correctness are entangled: the address is an input
to H, so a wrong address gives a wrong value.

### The binary stack invariant

After processing k leaves (out of 2^h), the stack heights (bottom to top,
decreasing) are exactly the positions of the set bits in k. Stack depth =
popcount(k). This is a carry-propagation invariant: adding a new leaf is
like adding 1 to k in binary, and the merge-while-equal-height loop is
carry propagation.

The stronger statement needed for the proof: the i-th stack entry (from
bottom) is not just "some node at height h_i" — it is specifically
Tree(h_i, s_i), where s_i is determined by the binary decomposition of k.
This is the *canonical subtree decomposition* of the interval [s, s+k).

### The address convention (critical, easy to get wrong)

RFC 8391 uses a counterintuitive convention: the treeHeight field in the
address for a hash call that *produces* a node at height h is set to h-1
(the children's height), not h. The treeIndex field is the *parent's*
index. This is confirmed by:
- Algorithm 9: increments treeHeight *after* RAND_HASH returns.
- Algorithm 13 (rootFromSig): sets treeHeight=k when computing height k+1.

The document's addr(ℓ,τ,h,j) notation means: the address used when
producing the node at height h, index j — with treeHeight field = h-1.

### The two address computation strategies (Lemma 0)

The RFC computes treeIndex statefully: starts at the leaf index and
applies (prev-1)/2 at each merge. The closed-form variant computes it
statelessly: at each merge at children's height node_h, it computes

  j = (s >> (node_h+1)) + ((idx-s) >> (node_h+1))

Both produce floor(idx / 2^{node_h+1}), the global index of the merged
node. Lemma 0 establishes this as a pure arithmetic fact — it is
straightforward and does not depend on algorithm-specific reasoning.

The alignment precondition s ≡ 0 (mod 2^h) is what makes s >> (node_h+1)
exact. When s = 0 the formula simplifies to idx >> (node_h+1); the
general case s ≠ 0 arises in XMSS-MT and in naive auth-path computation.

### XMSS-MT

XMSS-MT composes d layers of trees, each of height h/d. Outer address
fields (layer ℓ, tree τ) are set by the caller and must remain invariant
throughout all hash calls inside treehash — they are never touched by the
inner computation, only copied. This is Lemma 2 (trivial from the
algorithm's structure, but load-bearing for the theorem). The harder
XMSS-MT obligation is that the
s≠0 formula correctly globalises the node index within the layer's tree,
given that the outer fields identify which layer and tree we are in.

### What is NOT in scope for this document

- Auth path correctness (naive or BDS). The naive implementation
  (XMSS_NAIVE_AUTH_PATH) calls treehash on sub-intervals; its correctness
  follows from Theorem 1 plus a separate argument. BDS is significantly
  harder and deserves its own document.
- Security reductions. This document establishes the prerequisite
  (iterative = recursive with correct addresses). The reduction itself
  (collision-resistance, second-preimage-resistance) is a separate task.
- EasyCrypt syntax or mechanisation strategy.

## What has been done

All proof bodies have been filled in:

1. **Lemma 0 proof** (§4.0): Pure arithmetic. Part (a) shows the
   closed-form formula computes the correct global index via the
   alignment of s. Part (b) shows the RFC stateful formula agrees
   via an auxiliary claim about iterated `(x-1)/2`.

2. **Lemma 1 proof** (§4.1): Strong induction on k. This is the main
   proof — the inductive step maps the merge loop to binary carry
   propagation, establishes the merge precondition from the IH, and
   uses Lemma 0 for address correctness at each merge.

3. **Lemma 2 proof** (§6): By inspection of Algorithm 9 — the outer
   fields are inherited from the caller's address and never mutated.

4. **Theorem 2 proof** (§6): Combines Lemma 1 (inner-field correctness)
   and Lemma 2 (outer-field correctness).

5. **Appendix A**: Exact 32-byte field layout from RFC 8391 §2.5, with
   tables for all three address types, the domain separation rule, and
   serialisation notes.

## What remains to be done

- **Review**: The proofs should be checked by a mathematically
  sophisticated reader. Lemma 1 (the stack invariant induction) is the
  main proof and deserves the most scrutiny. Lemma 0 is supporting
  arithmetic.
- **EasyCrypt mechanisation**: The document is intended as a basis for
  a future mechanised proof. The formalisation strategy notes in §7
  remain relevant.

## Relevant files

- `proofs/treehash-equivalence.md` — the document itself
- `doc/rfc8391.txt` — the RFC; Algorithm 9 is at line 1351,
  Algorithm 13 at line 1700, address layout at §2.5

For understanding *why* the proof obligations exist (e.g. the closed-form
address variant, the s≠0 generalisation), the C implementation in
`impl/c/src/treehash.c` and its header are useful context.  However, the
proof document itself is a self-contained mathematical presentation that
does not reference any implementation.

## Style guidance

- **The document must be self-contained mathematics.** Do not reference
  any implementation (C, Jasmin, or otherwise) in the proof document.
  Algorithms are stated in pseudocode; proofs reference Algorithm 9
  and the RFC, not source files.
- Write mathematics precisely. Every quantifier matters.
- Do not hand-wave the address arguments — they are the point.
- **Lemma 1 is the heart of the document**; it carries the main
  inductive argument.  Lemma 0 is supporting arithmetic.
- The document uses $...$ for inline math and $$...$$ for display math,
  targeting eventual LaTeX conversion. Keep this convention.
- Proofs should be written to be checkable by a mathematically
  sophisticated reader, not just plausible-sounding.
