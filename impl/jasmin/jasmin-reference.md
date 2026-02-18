# Jasmin Language Reference for XMSS

A working reference for writing Jasmin code in this project. Not a substitute for
the full docs at https://jasmin-lang.readthedocs.io — use those for anything not here.

Primary reference implementations: https://github.com/formosa-crypto/libjade

---

## File conventions

| Extension | Role |
|-----------|------|
| `.jazz`   | Top-level file. Defines `export fn` symbols with C ABI. Minimal code — just imports and the export wrapper. |
| `.jinc`   | Included implementation. Contains the actual algorithm. Not compiled directly. |

```jasmin
// foo.jazz
require "foo.jinc"

export fn my_function(reg u64 out inp len) -> reg u64 {
  reg u64 r;
  _ = #init_msf();
  __my_function_impl(out, inp, len);
  ?{}, r = #set0();
  return r;
}
```

```
// In a Makefile:
jasminc -arch x86-64 foo.jazz -o foo.s
```

---

## Types

```jasmin
bool          // condition flag (from comparisons)
u8  u16  u32  u64    // unsigned integers
int           // compile-time integer (param only)

// Arrays — always fixed size, always on stack or register file
u8[32]        // 32-byte array
u64[4]        // four 64-bit words

// Storage qualifiers
reg u64       // lives in a register
stack u8[32]  // lives on the stack (fixed size required)
reg ptr u8[32]  // register holding a pointer to a stack array
stack ptr u8[32]  // stack slot holding a pointer to a stack array
```

---

## Functions

```jasmin
// Internal function (not exported)
fn __my_fn(reg u64 x, stack u64[4] buf) -> reg u64 { ... }

// Inlined at every call site (like a macro — no call instruction generated)
inline fn __helper(inline int n, reg u64 x) -> reg u64 { ... }

// Exported with C calling convention
export fn jade_xmss_sign(reg u64 sig sk msg mlen) -> reg u64 { ... }
```

Key points:
- `inline int` parameters are compile-time constants (usable as array sizes, loop bounds)
- Multiple return values: `fn foo() -> reg u64, reg u64 { ... return a, b; }`
- Discard a return value: `_, r = some_fn();`
- Assign flags: `?{cf, zf}, r = #ADD(a, b);` or discard all: `?{}, r = #set0();`

---

## Control flow

```jasmin
// For loop — bounds must be public (not secret-dependent)
for i = 0 to 64 { ... }

// While loop
while (cond) { ... }

// If/else
if (x == 0) { ... } else { ... }
```

No recursion. No goto. Loops must terminate with public bounds.

---

## Operators and intrinsics

```jasmin
// Arithmetic
r = x + y;       // addition (also: -, *, &, |, ^, ~)
r = x >> 3;      // logical shift right
r = x << 3;      // shift left
r = x >>>u 3;    // unsigned rotate right (not standard — use #ROR)

// x86 intrinsics (generate specific instructions)
r  = #ROR(x, 3);          // rotate right
r  = #ROL(x, 3);          // rotate left
?{}, r = #set0();          // xor reg,reg (zero without data dependency)
_ = #init_msf();           // Spectre v1 mitigation init (always at export fn entry)
r = #MSF(r, msf);          // mask with speculative flow value

// Memory
r = (u64)[ptr];            // load 64-bit word
(u64)[ptr] = r;            // store
r = (u64)[ptr + 8 * i];    // indexed load
r = #BSWAP(r);             // byte-swap (for big-endian output)
```

---

## Arrays

```jasmin
stack u8[32] buf;

// Byte access
buf[i] = x;
x = buf[i];

// Word-width access (little-endian by default)
t = (u64)[buf + 8 * i];    // load u64 at byte offset 8*i
(u64)[buf + 8 * i] = t;    // store u64

// Pass to function
__some_fn(buf);                  // by value (copy)
__some_fn(#copy(buf));           // explicit copy
__some_fn((stack ptr u8[32]) &buf);  // by pointer
```

---

## Security annotations (CT enforcement)

Jasmin enforces constant-time via an information-flow type system.

```jasmin
// Declare a variable as secret (must not flow to branches or memory addresses)
#[secret] reg u64 key;

// Declare as public (default for indices, lengths, etc.)
#[public] reg u64 i;

// Declassify: assert a secret value is safe to reveal (use sparingly, prove it)
r = #declassify(secret_val);

// init_msf: initialise speculative flow mask (required at every export fn entry)
_ = #init_msf();
```

The compiler will reject programs where secret values reach:
- Branch conditions (`if`, `while`)
- Memory addresses (array indices)

This is the primary CT guarantee. If a function touches key material, mark it `#[secret]` and let the compiler verify.

---

## Params (compile-time constants)

```jasmin
param int N = 32;    // usable as array size or loop bound
param int W = 16;    // Winternitz parameter

stack u8[N] buf;     // OK — N is a compile-time constant
for i = 0 to N { }  // OK
```

Our XMSS `XMSS_MAX_*` constants map directly to Jasmin `param int`.

---

## ADRS convention

Following C implementation rule J6 — ADRS is a `u32[8]` on the stack, manipulated
via `inline fn` setters, then serialised to `u8[32]` before passing to hash functions:

```jasmin
inline fn __adrs_set_type(stack u32[8] adrs, inline int t) -> stack u32[8] {
  adrs[3] = (u32) t;
  // zero words 4-7 as required by RFC 8391 §2.5
  adrs[4] = 0;  adrs[5] = 0;  adrs[6] = 0;  adrs[7] = 0;
  return adrs;
}

// Serialise to bytes before hashing
inline fn __adrs_to_bytes(stack u32[8] adrs) -> stack u8[32] {
  stack u8[32] buf;
  reg u32 w;
  inline int i;
  for i = 0 to 8 {
    w = adrs[i];
    w = #BSWAP(w);         // big-endian
    (u32)[buf + 4 * i] = w;
  }
  return buf;
}
```

---

## Project file layout

```
src/
  address.jinc       ADRS type and inline setters
  utils.jinc         ull_to_bytes, bytes_to_ull, ct_memcmp, memzero
  hash/
    sha256.jinc      SHA-256 compression + padding
    sha512.jinc      SHA-512 compression + padding
    shake128.jinc    SHAKE-128 (Keccak-based)
    shake256.jinc    SHAKE-256 (Keccak-based)
  wots.jinc          WOTS+ chain, sign, pkFromSig
  ltree.jinc         L-tree hash
  treehash.jinc      treehash and stack
  bds.jinc           BDS state and update functions
  xmss.jinc          XMSS keygen, sign, verify
  xmssmt.jinc        XMSS-MT keygen, sign, verify
  xmss.jazz          export fn wrappers (C ABI)
  xmssmt.jazz        export fn wrappers (C ABI)
test/
  (C harnesses that #include the exported header and link against .s files)
```

---

## Building

```bash
# Compile a .jazz file to x86-64 assembly
jasminc -arch x86-64 src/xmss.jazz -o src/xmss.s

# Check for constant-time violations specifically
jasminc -arch x86-64 -CT src/xmss.jazz

# The PostToolUse hook runs jasminc automatically after every .jazz file write.
```

---

## Resources

- Full language docs: https://jasmin-lang.readthedocs.io
- libjade (canonical Jasmin crypto implementations): https://github.com/formosa-crypto/libjade
  - Use the **`release/2023.05` branch** — `main` is mid-restructure and has no `.jazz` source files.
  - SHA-256 reference: `src/crypto_hash/sha256/amd64/ref/`
  - SHAKE-256 reference: `src/crypto_xof/shake256/amd64/ref/`
  - Keccak-f[1600] reference: `src/common/keccak/keccak1600/amd64/ref/`
- formosa-crypto organisation: https://github.com/formosa-crypto
- EasyCrypt (formal verification): installed via opam, pinned to dev version
  - Check pin before upgrading: `opam pin list | grep easycrypt`
