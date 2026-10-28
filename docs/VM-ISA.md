# RustCloak VM — bytecode ISA

`virt` (RUSTCLOAK_VM) replaces a function's body with a bytecode program and an interpreter for a
small register machine emitted in its place. This documents the ISA so the design is reviewable and
so the blue side (rust-deobf) has a reference. Everything here is **per-build, per-function** and
seed-randomized — two functions share no instruction set.

## Machine state
- **Registers**: a uniform `i64` register file (`alloca [N x i64]`). Values are kept
  **zero-extended** in their lane; width-sensitive opcodes operate at a declared width then
  re-zero-extend. Pointers live in a lane as an integer (`ptrtoint`/`inttoptr` at the edges).
- **Constant pool**: an `i64` array; `OP_CONST` loads pool entries into registers. Every constant
  the program needs — literals, `trunc` masks, folded `getelementptr` offsets — is collected here
  before code is emitted.
- **Argument buffer** + **callee table**: staged call arguments and the function-pointer table the
  `CALL` opcode indexes (direct, non-vararg, ≤6 integer/pointer args).
- **pc**: a byte offset into the bytecode (a PHI in the dispatch loop).

## Instruction encoding (4 bytes)
```
byte0 = opcode   : low 6 bits = slot, high 2 bits = width code (0=i8,1=i16,2=i32,3=i64)
byte1 = dst      ^ kd
byte2 = a        ^ ka      (branch/jump target low  byte, or pool index low)
byte3 = b        ^ kb      (branch/jump target high byte, or pool index high)
```
- **Operand bytes are XOR-encrypted** with per-build/per-function keys `kd/ka/kb`; the interpreter
  decrypts after fetch, so register indices, pool indices and branch targets are all hidden.
- **Synonym opcodes**: the 6-bit slot is one-to-many — each logical operation owns one or more
  slots (frequent ops own several), chosen at random per instruction, so no single byte dominates a
  frequency count. A decode table maps every slot back to its logical op.
- **Anti-tamper** (RUSTCLOAK_VM_INTEGRITY): the interpreter FNV-hashes its own bytecode at run time
  and folds any mismatch into `kd/ka/kb`, so a patched byte makes every operand decode wrong
  (no compare-and-branch to NOP out).

## Opcodes (logical)
| op | meaning |
|---|---|
| `RET a` / `RETV` | return `reg[a]` (truncated/inttoptr to the function return type) / return void |
| `CONST dst,idx` | `reg[dst] = pool[idx]` |
| `ADD SUB MUL AND OR XOR SHL LSHR ASHR UDIV SDIV UREM SREM` | width-W arithmetic/logic on `reg[a],reg[b]` -> `reg[dst]`, re-zero-extended |
| `EQ NE ULT ULE UGT UGE SLT SLE SGT SGE` | width-W integer compare -> `reg[dst]` (0/1) |
| `MOV dst,a` | full 64-bit copy (zext, ptr<->int, bitcast) |
| `CMOVNZ dst,a,b` | `if reg[a]!=0: reg[dst]=reg[b]` (lowers `select`) |
| `JMP t` / `JZ dst,t` / `JNZ dst,t` | unconditional / conditional jump to byte offset `t` |
| `LOAD dst,a` (W) | `reg[dst] = zext(*(iW*)reg[a])` |
| `STORE a,b` (W) | `*(iW*)reg[a] = trunc(reg[b], iW)` |
| `SEXT dst,a` (W) | sign-extend `reg[a]` from W bits to 64 |
| `PUSHARG a` | stage `reg[a]` as the next call argument |
| `CALL dst,idx` (W) | `reg[dst] = calleetable[idx](args...)`, re-zero-extended from width W |

## Eligibility (what stays native — correctness over coverage)
Left as native code: variable-argument functions; float/vector values; indirect calls; calls with
>6 args or non-standard return width; exception handling (`invoke`/landingpad); integer widths
outside {8,16,32,64} for width-sensitive ops; bytecode larger than 64 KiB (two-byte jump offsets).
`eligible()` rejects the whole function on any of these, so the VM never mis-models an operation.

## Lowering notes
- `select` -> `MOV dst,false; CMOVNZ dst,cond,true`.
- `getelementptr` -> base `MOV`, a stride `MUL`+`ADD` per variable index, one `ADD` of the folded
  constant offset (struct fields + constant indices).
- `trunc` -> `AND` with a pooled width mask; `zext` -> `MOV`; PHIs -> parallel `MOV`s via temporaries
  at each predecessor (critical edges are split first).

## Pipeline position
`virt` runs first, so the interpreter it emits is then itself run through `constenc`, `subst`,
`bogus` and `flatten`, and module strings through `strenc`.
