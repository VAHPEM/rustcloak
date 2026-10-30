# Security notes — license & anti-tamper gates

A red-team read of `License.cpp` and `AntiTamper.cpp`, what is already strong, the one structural
weakness, and what was changed.

## What is already strong
Both gates are **branch-free**. Neither emits a `if (license_ok) … else corrupt` that an analyst can
locate and NOP. Instead each folds `key = hash ^ expected` into an i64 that is **0 only when correct**
(right `RC_KEY` / intact `.text`), then XORs that key into a random ~75% of integer constants across
the module. With the key wrong, reachable constants silently corrupt; there is no single comparison
to patch, and `expected` is folded in at compile time (license) or read through a volatile load from
a tool-patched descriptor (anti-tamper), so the optimizer cannot pre-compute the delta.

## The structural weakness: a single constructor is the whole gate
Each gate hinges on **one constructor** that writes the key global (`lic_k` / `rc_k`). Defeat that one
constructor and the gate collapses:
- `lic_k` is initialized to **0** (the "unlocked" value). If an attacker stops the license ctor from
  running — zero its `.init_array` slot, or patch its body — `lic_k` stays 0 and every keyed constant
  is identity: **a permanent unlock, no key needed.**
- `rc_k` has the same shape, but anti-tamper partly self-protects: its own ctor sits in the hashed
  section, so NOP'ing it changes the hash.

### Fix applied (this change): integrity now covers the license gate
The pass order in `Plugin.cpp` was AntiTamper → License, so anti-tamper sectioned and hashed the code
**before the license constructor existed** — the license ctor was never integrity-protected. Order is
now **License → ImportHide → AntiTamper (last)**, so the license gate's constructor and keyed
constants are inside the hashed section. With `RUSTCLOAK_LICENSE` **and** `RUSTCLOAK_ANTITAMPER` on,
an attacker can no longer silently NOP the license ctor: doing so changes the section hash, `rc_k`
becomes nonzero, and the program corrupts. Verified: `difftest` 6/6, `combos` (incl. LICENSE+ANTITAMPER),
`license.sh`, `antitamper.sh`, `tamper.sh` all pass.

### Residual weakness (not yet addressed — needs maintainer design)
- **License without anti-tamper** gets no ctor protection; the single-ctor unlock still applies.
  Recommend: document that `RUSTCLOAK_LICENSE` should be paired with `RUSTCLOAK_ANTITAMPER`, or make
  License refuse/ warn when anti-tamper is off.
- **One choke point remains** even with both on: a sufficiently determined attacker who defeats
  anti-tamper (recompute+patch the descriptor's `expected`, or emulate past the check) still has one
  ctor to neutralize. Hardening directions, in order of value:
  1. **Multiple, independent key constructors** so there is no single `.init_array` slot to remove;
     the key becomes a sum/xor of several ctors' contributions.
  2. **Key provenance beyond a constructor** — derive part of `lic_k`/`rc_k` from a runtime syscall
     the way `RUSTCLOAK_STRENC_SYSCALLKEY` now does for string keys (correct on a real host, wrong
     under constructor-replay emulation).
  3. **Initialize `lic_k` to a nonzero poison** so that skipping the ctor *breaks* the program rather
     than unlocking it — but only after confirming no keyed constant is read by an earlier-priority
     constructor (otherwise a correct-key program misbehaves pre-main). This needs a dominance/`ctor`
     -ordering analysis; left for a focused change.
