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
When the outer fields are fixed, an address is uniquely identified by
$(\mathsf{type}, \mathsf{treeHeight}, \mathsf{treeIndex})$; for hash-tree
nodes we abbreviate this to $(h, j)$ where $h = \mathsf{treeHeight}$ and
$j = \mathsf{treeIndex}$.

Define the *canonical hash-tree address* for a node at height $h$ and index $j$,
within a tree with outer fields $(\ell, \tau)$, as:

$$\mathsf{addr}(\ell, \tau, h, j) := \text{(type=HASH, layer=}\ell\text{, tree=}\tau\text{, treeHeight=}h\text{, treeIndex=}j\text{)}$$

*(Note: RFC 8391 sets treeHeight to the height of the children, not the parent.
We follow the RFC convention; the exact mapping is pinned in Appendix A.)*

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
The stack invariant and algorithm are given in Figure 1 below.

**Figure 1: Iterative treehash**

```
Stack σ := []
for idx = s to s + 2^h - 1:
    leaf_val := leaf(idx)
    push(σ, (leaf_val, 0))
    while |σ| ≥ 2 and height(σ[-2]) = height(σ[-1]):
        node_h  := height(σ[-1])          // height of children
        (R, _)  := pop(σ)
        (L, _)  := pop(σ)
        j       := idx >> (node_h + 1)    // index of parent node
        adrs    := addr(ℓ, τ, node_h, j)
        v       := H(adrs, L, R)
        push(σ, (v, node_h + 1))
return value(σ[0])
```

*(The index formula `j := idx >> (node_h + 1)` assumes $s = 0$; the general
formula for arbitrary $s$ is given in Appendix A.)*

---

## 4. The Stack Invariant

The key to the equivalence proof is the following invariant, which holds
after each outer loop iteration.

**Lemma 1 (Stack invariant).** After processing leaves $s, s+1, \ldots,
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

*[To be filled in: exact byte layout and field semantics for hash-tree
addresses, pinning the treeHeight/treeIndex convention and the $s \neq 0$
index formula.]*
