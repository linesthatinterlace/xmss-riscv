# Treehash Equivalence: Recursive and Iterative Definitions

**Status**: skeleton — structure only, proofs to be filled in.

---

## 1. Introduction

The XMSS treehash computation (RFC 8391, Algorithm 9) is specified iteratively,
using a stack to avoid storing the whole tree in memory.
Security proofs, however, are most naturally stated against a *recursive*
definition of the tree, where the root is defined by structural induction on
height.

This document establishes a formal equivalence between the two formulations,
for both single-tree XMSS and multi-layer XMSS-MT.
The equivalence is not merely about output values: because the hash function
takes an *address* as input (for domain separation), the proof must also show
that every internal hash call uses the correct address.
This address-correctness is the main technical difficulty.

The document is intended to be self-contained and to serve as a basis for
a future mechanised proof (e.g. in EasyCrypt), so definitions are stated
precisely and with an eye toward program logic.

---

## 2. Notation and Preliminaries

Fix a parameter set with:
- $n$: hash output length in bytes.
- $h$: tree height (number of levels above the leaves; the tree has $2^h$ leaves).
- $w$: Winternitz parameter (relevant for WOTS+, mentioned for completeness).

We write $[a, b)$ for the integer interval $\{a, a+1, \ldots, b-1\}$.

### 2.1 Addresses

An *address* $\mathsf{adrs}$ is a structured 32-byte value with fields including:
- $\mathsf{layer}$: the hypertree layer (0 for XMSS; $0, \ldots, d-1$ for XMSS-MT).
- $\mathsf{tree}$: the tree index within a layer (XMSS-MT only).
- $\mathsf{type}$: distinguishes OTS, L-tree, and hash-tree computations.
- $\mathsf{treeHeight}$, $\mathsf{treeIndex}$: position within the hash tree.

We say an address is *outer-fixed* at $(\ell, \tau)$ if its $\mathsf{layer}$ and
$\mathsf{tree}$ fields are fixed to $\ell$ and $\tau$ respectively.

**Address convention (RFC 8391).** This is a critical point that must be pinned
precisely. When the RFC computes an internal node at height $h$ (i.e., the parent
of two nodes at height $h-1$), it sets:

$$\mathsf{treeHeight} = h - 1 \quad \text{(the height of the \emph{children}, not the parent)}$$
$$\mathsf{treeIndex} = j \quad \text{(the index of the \emph{parent} node among nodes at height } h\text{)}$$

This is confirmed by Algorithm 9 (treeHash), which increments treeHeight *after*
calling RAND\_HASH, and by Algorithm 13 (rootFromSig), which sets
$\mathsf{treeHeight} = k$ when computing the node at height $k+1$.

We adopt this convention throughout. Define the *canonical hash-tree address* for
computing a node at height $h$ (with index $j$) within a tree with outer fields
$(\ell, \tau)$ as:

$$\mathsf{addr}(\ell, \tau, h, j) := \text{(type=HASH, layer=}\ell\text{, tree=}\tau\text{, treeHeight=}h{-}1\text{, treeIndex=}j\text{)}$$

That is, $\mathsf{addr}(\ell, \tau, h, j)$ is the address used as input to $H$
when *producing* the node at height $h$, index $j$. The treeHeight field carries
the value $h-1$.

### 2.2 Primitive hash functions

We treat the following as black-box primitives:

- $\mathsf{leaf}(i; \mathsf{SK}, \mathsf{PK\_SEED}, \mathsf{adrs})$: the $n$-byte
  leaf value at index $i$, computed as $\mathsf{lTree}(\mathsf{WOTS\text{+}genPK}(\ldots))$.
  The address $\mathsf{adrs}$ must have type OTS (for genPK) and type LTREE
  (for lTree); we suppress the internal address details here.

- $H(\mathsf{adrs}, L, R)$: the $n$-byte hash of two $n$-byte nodes $L$ and $R$
  under address $\mathsf{adrs}$.

---

## 3. Two Definitions of the XMSS Tree

### 3.1 Recursive definition

Fix outer fields $(\ell, \tau)$, secret seed $\mathsf{SK}$, public seed
$\mathsf{PK\_SEED}$, and starting leaf index $s$ (a multiple of $2^h$).

Define $\mathsf{Tree}(h, s)$ by induction on $h$:

$$\mathsf{Tree}(0, i) \;:=\; \mathsf{leaf}(i;\, \mathsf{SK},\, \mathsf{PK\_SEED},\, \cdot)$$

$$\mathsf{Tree}(h, s) \;:=\; H\!\left(\mathsf{addr}(\ell, \tau, h, s/2^h),\;\; \mathsf{Tree}(h-1, s),\;\; \mathsf{Tree}(h-1, s + 2^{h-1})\right)$$

The *root* of the XMSS tree is $\mathsf{Tree}(H, 0)$ where $H$ is the tree height.

### 3.2 Iterative definition (Algorithm 9)

The iterative algorithm maintains a stack $\sigma$ of pairs $(v, k)$ where $v$
is an $n$-byte node value and $k \geq 0$ is its height.

There are two variants of interest, which differ only in how they compute the
address for each merge. Both are given here because establishing their
equivalence is a central proof obligation (see Lemma 0 below).

**Figure 1a: RFC 8391 Algorithm 9 (stateful address)**

The RFC tracks treeIndex as mutable state, updated incrementally at each merge:

```
Stack σ := []
for i = 0 to 2^h - 1:
    idx := s + i
    leaf_val := leaf(idx)
    ADRS.setTreeHeight(0)
    ADRS.setTreeIndex(idx)           // start: leaf's own index
    push(σ, (leaf_val, 0))
    while |σ| ≥ 2 and height(σ[-2]) = height(σ[-1]):
        ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2)   // parent index
        (L, _) := pop(σ[-2]);  (R, _) := pop(σ[-1])
        v := RAND_HASH(L, R, SEED, ADRS)
        ADRS.setTreeHeight(ADRS.getTreeHeight() + 1)        // after the hash
        push(σ, (v, ADRS.getTreeHeight()))
return pop(σ)
```

**Figure 1b: C implementation (closed-form address)**

The C implementation (introduced in the initial commit) computes treeIndex
from scratch at each merge, with no carried address state between iterations:

```
Stack σ := []
for idx = s to s + 2^h - 1:
    leaf_val := leaf(idx)
    push(σ, (leaf_val, 0))
    while |σ| ≥ 2 and height(σ[-2]) = height(σ[-1]):
        node_h := height(σ[-2])                              // children's height
        (L, _) := pop(σ[-2]);  (R, _) := pop(σ[-1])
        j := (s >> (node_h + 1)) + ((idx - s) >> (node_h + 1))
        adrs := addr(ℓ, τ, node_h + 1, j)                   // using our notation
        v := H(adrs, L, R)
        push(σ, (v, node_h + 1))
return value(σ[0])
```

The formula for $j$ computes the global index of the parent node directly
from the current loop variable `idx`, the subtree start `s`, and the merge
height `node_h`, without reference to any previous iteration's address state.

---

## 4. Key Lemmas

### 4.0 The Address Formula Lemma

**This is a central proof obligation.** The C implementation deliberately
diverges from the RFC pseudocode in how it computes treeIndex. The two
formulas must be shown to always agree, or the C implementation is not a
correct realisation of RFC 8391 — regardless of whether the node *values*
are correct.

**Lemma 0 (Address formula equivalence).** Suppose $s$ is a multiple of
$2^h$ (the alignment precondition). At any merge performed during the
processing of leaf $\mathsf{idx} \in [s, s + 2^h)$ at children's height
$\mathsf{node\_h}$:

1. The RFC stateful formula and the C closed-form formula both produce the
   same treeIndex value $j$.

2. Explicitly: letting $q = (\mathsf{idx} - s) \gg (\mathsf{node\_h} + 1)$,
   we have:
   $$j \;=\; (s \gg (\mathsf{node\_h} + 1)) + q$$
   and this equals the global index of the parent node, i.e. the index of
   the unique node at height $\mathsf{node\_h} + 1$ whose leaf-range
   contains $\mathsf{idx}$.

3. The precondition for the merge — that two stack entries of height
   $\mathsf{node\_h}$ are present — is equivalent to bits $0$ through
   $\mathsf{node\_h}$ of $(\mathsf{idx} - s)$ all being $1$.
   This is the key arithmetic fact that makes the shift formula correct:
   since those low bits are all $1$, the shift $(\mathsf{idx} - s) \gg
   (\mathsf{node\_h} + 1)$ discards exactly the part of $\mathsf{idx} - s$
   that is "within" the subtree being merged.

**Proof.** *[To be filled in — induction on the carry structure of
$(\mathsf{idx} - s)$, using the binary stack invariant.]*

**Remark.** The alignment condition $s \equiv 0 \pmod{2^h}$ is what makes
$s \gg (\mathsf{node\_h} + 1)$ exact (no rounding). The RFC checks this
condition explicitly: `if (s % (1 << t) != 0) return -1`. Without it,
the C formula gives the wrong global index.

---

### 4.1 The Stack Invariant

The key to the equivalence proof is the following invariant, which holds
after each outer loop iteration.

**Lemma 1 (Stack invariant).** *(Depends on Lemma 0 for the address part.)* After processing leaves $s, s+1, \ldots,
s+k-1$ (i.e. after $k$ iterations of the outer loop, $1 \leq k \leq 2^h$),
the stack $\sigma$ satisfies:

1. **Heights**: the heights of stack entries, read from bottom to top, are
   exactly the positions of the set bits in $k$, in decreasing order.
   In particular, $|\sigma| = \mathsf{popcount}(k)$.

2. **Values**: if the $i$-th stack entry (from the bottom, 0-indexed) has
   height $h_i$, then its value is $\mathsf{Tree}(h_i,\, s_i)$, where
   $s_i = s + \sum_{j > i} 2^{h_j}$ is the starting leaf of the
   corresponding canonical subtree.

3. **Addresses**: every internal hash call made during the computation of
   $\mathsf{Tree}(h_i, s_i)$ used the canonical address $\mathsf{addr}(\ell, \tau, \cdot, \cdot)$.

**Proof.** By induction on $k$. *[To be filled in.]*

**Corollary (Termination and correctness).** At $k = 2^h$, $|\sigma| = 1$
and $\sigma[0] = (\mathsf{Tree}(h, s), h)$. The algorithm returns
$\mathsf{Tree}(h, s)$ with all internal hashes at canonical addresses.

---

## 5. Main Theorem: XMSS

**Theorem 1 (Iterative–recursive equivalence, XMSS).** Let $p$ be an XMSS
parameter set with tree height $H$. Let $\mathsf{SK}$, $\mathsf{PK\_SEED}$ be
fixed. Then:

$$\mathsf{treehash}(\mathsf{SK}, \mathsf{PK\_SEED}, 0, 2^H) \;=\; \mathsf{Tree}(H, 0)$$

and every call to $H$ inside $\mathsf{treehash}$ uses the canonical address
for the node it computes.

**Proof.** Immediate from Lemma 1 at $k = 2^H$. $\square$

---

## 6. Extension to XMSS-MT

XMSS-MT composes $d$ layers of XMSS trees, each of height $h' = H/d$.
A tree at layer $\ell$ and tree-index $\tau$ is computed by calling treehash
with outer address fields fixed to $(\ell, \tau)$.

The additional difficulty over the single-tree case is:

- **Shared hash**: all layers use the same hash function $H$, with domain
  separation achieved entirely through the address fields $\mathsf{layer}$
  and $\mathsf{tree}$. The proof must track that these outer fields are
  consistently set for every hash call throughout the computation.

- **Offset starts ($s \neq 0$)**: trees at layer $\ell > 0$ are indexed
  within their layer; the starting leaf $s$ for a subtree call is not
  necessarily 0. The address index formula must be shown to correctly
  globalise the local node index.

**Lemma 2 (Outer-field consistency).** For any call to $\mathsf{treehash}$
with outer fields $(\ell, \tau)$ and start $s$, every hash call inside uses
an address with $\mathsf{layer} = \ell$ and $\mathsf{tree} = \tau$.

**Proof.** *[To be filled in — follows from the address being copied from
the caller's adrs and only inner fields being mutated.]*

**Theorem 2 (Iterative–recursive equivalence, XMSS-MT).** For each layer
$\ell \in [0, d)$ and tree-index $\tau$, the iterative treehash with outer
fields $(\ell, \tau)$ computes $\mathsf{Tree}_{\ell,\tau}(h', 0)$ (the
recursive tree for that layer and tree), with every internal hash call at
the canonical address for that layer and tree.

**Proof.** *[To be filled in — combine Lemma 1 and Lemma 2.]*

---

## 7. Remarks toward Formalisation

A mechanised proof in EasyCrypt (or similar) will need to:

- Represent the stack as a concrete data structure with a bounded-size
  invariant; the bound $h+1$ follows from Lemma 1(1).
- State the loop invariant (Lemma 1) as a loop annotation in a program logic.
- Handle the address arithmetic (`j := idx >> (node_h + 1)`) concretely;
  this is where most of the arithmetic reasoning lives.
- Lift from the single-tree to the multi-tree case by parametrising over
  $(\ell, \tau)$ and showing independence of inner-field computations from
  outer fields.

The fact that the iterative and recursive definitions are extensionally
equivalent does *not* immediately give security: the security proof also
needs the recursive structure to apply the collision-resistance and
second-preimage-resistance of $H$ at each level. The equivalence theorem
here is a prerequisite for that reduction.

---

## Appendix A: Address Conventions (RFC 8391)

The treeHeight/treeIndex convention is stated in Section 2.1 and is pinned
against two RFC algorithms:

- **Algorithm 9** (treeHash): sets `treeHeight` before the merge, increments
  it *after* `RAND_HASH` returns. At the point of the hash call, treeHeight
  holds the children's height.
- **Algorithm 13** (rootFromSig): sets `treeHeight = k` in the loop header
  when computing the node at height $k+1$.

Both are consistent: the treeHeight field in the address encodes the height
of the *inputs* to the hash, not the output.

*[To be filled in: exact 32-byte field layout from RFC 8391 Section 2.7.3,
for use in the mechanised proof.]*
