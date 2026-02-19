# CLAUDE.md — proofs/

## What this directory is

Formal mathematical proofs supporting the correctness of the XMSS/XMSS-MT
implementations in `impl/`. Currently contains one document:

- `treehash-equivalence.md` — proof skeleton for the equivalence of the
  iterative and recursive definitions of the XMSS Merkle tree, for both
  XMSS and XMSS-MT. **Status: skeleton only — theorem statements and
  lemma structure are in place; proof bodies are stubs.**

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

### The two address computation strategies (Lemma 0 — central obligation)

The RFC computes treeIndex statefu lly: starts at the leaf index and
applies (prev-1)/2 at each merge. The C implementation computes it
statlessly: at each merge at children's height node_h, it computes

  j = (s >> (node_h+1)) + ((idx-s) >> (node_h+1))

These must be shown equal. The key arithmetic fact: at the moment of a
merge at height node_h, bits 0..node_h of (idx-s) are all 1 (binary
carry precondition). This means (idx-s) >> (node_h+1) discards exactly
the "within-subtree" bits, leaving the subtree's position within [s, s+2^h).
The term s >> (node_h+1) then offsets to the global index — this step
requires s ≡ 0 (mod 2^h) (the alignment precondition).

The xmss-reference (`third_party/xmss-reference/xmss_core.c`) also uses
the closed-form approach (not the RFC stateful one) but only for s=0, so
it only needs `idx >> (node_h+1)`. Our s≠0 generalisation is what
requires proof.

### XMSS-MT

XMSS-MT composes d layers of trees, each of height h/d. Outer address
fields (layer ℓ, tree τ) are set by the caller and must remain invariant
throughout all hash calls inside treehash — they are never touched by the
inner computation, only copied. This is Lemma 2 (trivial from code, but
load-bearing for the theorem). The harder XMSS-MT obligation is that the
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

## What remains to be done

The document has complete theorem/lemma statements but stub proofs. In
order of dependency:

1. **Lemma 0 proof**: arithmetic argument about the closed-form address
   formula. Self-contained; uses only the binary carry precondition and
   the alignment of s. This is the most novel argument.

2. **Lemma 1 proof**: induction on k. Base case k=1 is straightforward.
   Inductive step: process one more leaf, run the merge loop, show the
   invariant is maintained. The address part of Lemma 1 cites Lemma 0.

3. **Lemma 2 proof**: immediate from code inspection — the outer fields
   are set by copying adrs before any inner-field mutation. Brief.

4. **Theorem 2 proof**: combine Lemmas 1 and 2. Should be short.

5. **Appendix A**: pin the exact 32-byte field layout from RFC 8391
   §2.7.3. Needed for any mechanised proof.

## Relevant files

- `proofs/treehash-equivalence.md` — the document itself
- `impl/c/src/treehash.c` — the C implementation being proved correct
- `impl/c/src/treehash.h` — API and documentation
- `doc/rfc8391.txt` — the RFC; Algorithm 9 is at line 1351,
  Algorithm 13 at line 1700, address layout at §2.7.3
- `third_party/xmss-reference/xmss_core.c` — reference implementation;
  treehash is at line 19 (note the comment at line 67 about the address
  convention, and that it only handles s=0)

## Style guidance

- Write mathematics precisely. Every quantifier matters.
- Do not hand-wave the address arguments — they are the point.
- Lemma 0 is the heart of the document; give it the most care.
- The document uses $...$ for inline math and $$...$$ for display math,
  targeting eventual LaTeX conversion. Keep this convention.
- Proofs should be written to be checkable by a mathematically
  sophisticated reader, not just plausible-sounding.
