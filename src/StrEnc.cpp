//===- StrEnc.cpp - string-literal encryption ------------------------------===//
//
// Every private constant i8 string is encrypted in the object with a per-string keystream, the
// global is made writable, and the strings are decrypted at run time, so the plaintext never
// exists statically -- `strings`/FLOSS see only ciphertext. Several knobs trade behaviour for
// analysis difficulty, so the blue side (rust-deobf) gets a spectrum of test cases:
//
//   default                     linear keystream `seed + i`, decrypted eagerly by one startup ctor
//   RUSTCLOAK_STRENC_CIPHER     per-string non-linear LCG keystream instead of `seed + i`
//   RUSTCLOAK_LAZY              decrypt each string on first use (no gathered ctor), in place
//   RUSTCLOAK_STRENC_CALLSITE   decrypt on first use into a SEPARATE buffer; the global stays
//                               ciphertext at rest (a dump of the global's section never shows text)
//   RUSTCLOAK_ANTIEMU           key the decryption on a marker a ctor sets before main, so a
//                               deobfuscator that emulates the decryptor in isolation gets garbage
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdlib>
#include <vector>

using namespace llvm;

namespace {

// Linear-congruential constants (glibc's rand); the runtime helper and the compile-time
// encryption below run the SAME recurrence so they agree byte-for-byte.
static const uint32_t LCG_MUL = 1103515245u, LCG_ADD = 12345u;

struct EncTarget { GlobalVariable *G; uint32_t seed; uint64_t len; };

// Compile-time encryption: XOR each byte with the keystream the runtime helper will reproduce.
//   linear : ks[i] = (uint8_t)(seed + i)
//   cipher : an LCG seeded per string -- ks[i] = high byte of the i-th LCG state
void xorKeystream(std::vector<uint8_t> &buf, uint32_t seed, bool cipher) {
  uint32_t state = seed;
  for (size_t i = 0; i < buf.size(); i++) {
    uint8_t ks;
    if (cipher) {
      state = state * LCG_MUL + LCG_ADD;
      ks = (uint8_t)(state >> 24);
    } else {
      ks = (uint8_t)(seed + i);
    }
    buf[i] ^= ks;
  }
}

// A shared decrypt helper: void dec(i8* p, i64 len, i32 seed). Built once per module; its keystream
// matches xorKeystream for the chosen mode.
Function *getDecHelper(Module &M, bool cipher) {
  LLVMContext &Ctx = M.getContext();
  if (Function *F = M.getFunction(rustcloak::anon("xorh")))
    return F;
  Type *I8 = Type::getInt8Ty(Ctx), *I32 = Type::getInt32Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::getUnqual(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), {Ptr, I64, I32}, false);
  Function *F = Function::Create(FT, GlobalValue::InternalLinkage, rustcloak::anon("xorh"), M);
  Argument *P = F->getArg(0), *Len = F->getArg(1), *Seed = F->getArg(2);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Cond = BasicBlock::Create(Ctx, "cond", F);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", F);

  IRBuilder<> B(Entry);
  AllocaInst *I = B.CreateAlloca(I64, nullptr, "i");
  B.CreateStore(ConstantInt::get(I64, 0), I);
  AllocaInst *St = nullptr;
  if (cipher) {                           // running LCG state, seeded once
    St = B.CreateAlloca(I32, nullptr, "st");
    B.CreateStore(Seed, St);
  }
  B.CreateBr(Cond);

  B.SetInsertPoint(Cond);
  Value *iv = B.CreateLoad(I64, I, "iv");
  B.CreateCondBr(B.CreateICmpULT(iv, Len), Body, Exit);

  B.SetInsertPoint(Body);
  Value *ks;
  if (cipher) {
    Value *s = B.CreateLoad(I32, St);
    s = B.CreateAdd(B.CreateMul(s, ConstantInt::get(I32, LCG_MUL)), ConstantInt::get(I32, LCG_ADD));
    B.CreateStore(s, St);
    ks = B.CreateTrunc(B.CreateLShr(s, ConstantInt::get(I32, 24)), I8);
  } else {
    ks = B.CreateAdd(B.CreateTrunc(Seed, I8), B.CreateTrunc(iv, I8));
  }
  Value *ptr = B.CreateGEP(I8, P, iv);
  Value *b = B.CreateLoad(I8, ptr);
  B.CreateStore(B.CreateXor(b, ks), ptr);
  B.CreateStore(B.CreateAdd(iv, ConstantInt::get(I64, 1)), I);
  B.CreateBr(Cond);

  B.SetInsertPoint(Exit);
  B.CreateRetVoid();
  return F;
}

// Anti-emulation (RUSTCLOAK_ANTIEMU). A static deobfuscator that recovers strings by emulating the
// decrypt function IN ISOLATION (as rust-deobf's engine does) never runs the program's global
// constructors first. So we key the decryption on a marker global that a *separate* constructor
// sets to `magic` before main: at real runtime marker==magic and the seed is correct, but under
// isolated emulation the marker ctor did not run, marker is still 0, and the seed is wrong -- the
// emulated plaintext is garbage. (The blue counter is to run the constructors before emulating.)
struct AntiEmu { GlobalVariable *marker; uint32_t magic; };

// The i32 seed to hand the helper: a plain constant, or -- under anti-emulation -- a value that
// XOR-cancels to the real seed only when the marker holds `magic`.
Value *seedValue(IRBuilder<> &B, LLVMContext &Ctx, uint32_t seed, const AntiEmu *ae) {
  Type *I32 = Type::getInt32Ty(Ctx);
  if (!ae)
    return ConstantInt::get(I32, seed);
  LoadInst *m = B.CreateLoad(I32, ae->marker);
  m->setVolatile(true);                                  // keep the optimizer from folding it away
  return B.CreateXor(ConstantInt::get(I32, seed ^ ae->magic), m);
}

// A constructor (run before the decryptor and before main) that stores `magic` into the marker.
void emitMarkerCtor(Module &M, const AntiEmu &ae) {
  LLVMContext &Ctx = M.getContext();
  Function *C = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                 GlobalValue::InternalLinkage, rustcloak::anon("mkc"), M);
  IRBuilder<> B(BasicBlock::Create(Ctx, "entry", C));
  B.CreateStore(ConstantInt::get(Type::getInt32Ty(Ctx), ae.magic), ae.marker)->setVolatile(true);
  B.CreateRetVoid();
  appendToGlobalCtors(M, C, 0);                          // priority 0: runs before the decryptor (1)
}

// RUSTCLOAK_STRENC_SELFKEY: a constructor that COMPUTES the marker at run time as FNV-1a-32 over
// `len` bytes of `anchor` (the still-encrypted string data), instead of storing a constant. `magic`
// is the same hash computed at compile time, so at run time marker == magic and the decryption is
// correct -- but a static deobfuscator can no longer read a stored `magic`; to learn it, it must
// actually execute this hash over the real ciphertext. Runs at priority 0 (before the decryptor at
// 1), so it hashes ciphertext. Because the marker also depends on the exact ciphertext bytes, any
// edit to the encrypted data changes the key and corrupts every decrypted string (anti-tamper bonus).
void emitComputedMarkerCtor(Module &M, const AntiEmu &ae, GlobalVariable *anchor, uint64_t len) {
  LLVMContext &Ctx = M.getContext();
  Type *I8 = Type::getInt8Ty(Ctx), *I32 = Type::getInt32Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Function *C = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                 GlobalValue::InternalLinkage, rustcloak::anon("mkc"), M);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", C);
  BasicBlock *Cond = BasicBlock::Create(Ctx, "cond", C);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", C);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", C);
  IRBuilder<> B(Entry);
  AllocaInst *I = B.CreateAlloca(I64);
  B.CreateStore(ConstantInt::get(I64, 0), I);
  AllocaInst *H = B.CreateAlloca(I32);
  B.CreateStore(ConstantInt::get(I32, 2166136261u), H);    // FNV-1a-32 offset basis
  B.CreateBr(Cond);
  B.SetInsertPoint(Cond);
  Value *iv = B.CreateLoad(I64, I);
  B.CreateCondBr(B.CreateICmpULT(iv, ConstantInt::get(I64, len)), Body, Exit);
  B.SetInsertPoint(Body);
  Value *bb = B.CreateLoad(I8, B.CreateGEP(I8, anchor, iv));
  Value *h = B.CreateMul(B.CreateXor(B.CreateLoad(I32, H), B.CreateZExt(bb, I32)),
                         ConstantInt::get(I32, 16777619u));  // FNV-1a-32 prime
  B.CreateStore(h, H);
  B.CreateStore(B.CreateAdd(iv, ConstantInt::get(I64, 1)), I);
  B.CreateBr(Cond);
  B.SetInsertPoint(Exit);
  B.CreateStore(B.CreateLoad(I32, H), ae.marker)->setVolatile(true);
  B.CreateRetVoid();
  appendToGlobalCtors(M, C, 0);
}

// Eager mode: one global constructor that decrypts all the given strings before main().
void emitStartupCtor(Module &M, Function *Helper, ArrayRef<EncTarget> targets, const AntiEmu *ae) {
  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *Ctor = Function::Create(FT, GlobalValue::InternalLinkage, rustcloak::anon("dctor"), M);
  IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Ctor));
  Type *I64 = Type::getInt64Ty(Ctx);
  for (auto &T : targets) {
    Value *P = B.CreateBitCast(T.G, PointerType::getUnqual(Ctx));
    B.CreateCall(Helper, {P, ConstantInt::get(I64, T.len), seedValue(B, Ctx, T.seed, ae)});
  }
  B.CreateRetVoid();
  appendToGlobalCtors(M, Ctor, ae ? 1 : 0);              // after the marker ctor when anti-emu is on
}

// Rewrite every ConstantExpr that uses G (e.g. a `getelementptr` into the array) into an equivalent
// instruction at each site that uses it, so afterwards all of G's uses are plain instruction
// operands the getter can be threaded through.
void expandConstantUsers(GlobalVariable *G) {
  bool changed = true;
  while (changed) {
    changed = false;
    for (User *U : llvm::make_early_inc_range(G->users())) {
      auto *CE = dyn_cast<ConstantExpr>(U);
      if (!CE)
        continue;
      for (Use &CU : llvm::make_early_inc_range(CE->uses())) {
        auto *I = dyn_cast<Instruction>(CU.getUser());
        if (!I)
          continue;                      // nested constexpr: handled on a later sweep
        Instruction *ip = I;
        if (auto *PN = dyn_cast<PHINode>(I))
          ip = PN->getIncomingBlock(CU)->getTerminator();
        Instruction *ni = CE->getAsInstruction(ip);
        CU.set(ni);
        changed = true;
      }
    }
  }
}

// Lazy mode (RUSTCLOAK_LAZY): give one encrypted global its own getter that decrypts it on first
// use -- guarded by a flag -- and returns its pointer, then redirect every use of the global to a
// call of that getter. The plaintext then exists in memory only once the string is actually used,
// and only for reached strings. Under RUSTCLOAK_STRENC_CALLSITE the getter decrypts into a SEPARATE
// sibling buffer and returns that, so the original global stays ciphertext at rest even after use.
// Returns false and changes nothing if the global has a use that is not a plain instruction operand
// (e.g. a ConstantExpr or a global initializer), so the caller can fall back to eager decryption.
// (The flag check is not synchronised; concurrent first-touch from several threads would need a
// once-guard -- noted for a future revision.)
bool makeLazy(Module &M, Function *Helper, const EncTarget &T, const AntiEmu *ae, bool callsite) {
  LLVMContext &Ctx = M.getContext();
  Type *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::getUnqual(Ctx);
  GlobalVariable *G = T.G;

  expandConstantUsers(G);
  std::vector<Use *> uses;               // snapshot before we add the getter's own uses of G
  for (Use &U : G->uses()) {
    if (!isa<Instruction>(U.getUser()))
      return false;                      // not safely redirectable -> defer to the eager ctor
    uses.push_back(&U);
  }
  if (uses.empty())
    return true;                         // encrypted but never referenced: nothing to redirect

  // call-site mode: decrypt into a fresh sibling buffer (initialised to the same ciphertext), so the
  // original global is never written and stays ciphertext at rest.
  GlobalVariable *dec = G;
  if (callsite) {
    dec = new GlobalVariable(M, G->getValueType(), /*isConstant=*/false,
                             GlobalValue::InternalLinkage, G->getInitializer(), rustcloak::anon("b"));
    dec->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
  }

  // Thread-safe exactly-once guard: the XOR keystream is self-inverse, so decrypting twice would
  // re-encrypt. A 3-state atomic flag (0=init, 1=decrypting, 2=done) lets exactly one thread
  // decrypt while any concurrent first-touchers spin until it publishes `done`.
  Type *I32g = Type::getInt32Ty(Ctx);
  auto *Flag = new GlobalVariable(M, I32g, /*isConstant=*/false, GlobalValue::InternalLinkage,
                                  ConstantInt::get(I32g, 0), rustcloak::anon("f"));
  Function *Get = Function::Create(FunctionType::get(Ptr, false),
                                   GlobalValue::InternalLinkage, rustcloak::anon("g"), M);
  BasicBlock *entry = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *tryb = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *decbb = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *spin = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *done = BasicBlock::Create(Ctx, "", Get);
  IRBuilder<> B(entry);
  LoadInst *s0 = B.CreateLoad(I32g, Flag);
  s0->setAtomic(AtomicOrdering::Acquire); s0->setAlignment(Align(4));
  B.CreateCondBr(B.CreateICmpEQ(s0, ConstantInt::get(I32g, 2)), done, tryb);
  B.SetInsertPoint(tryb);
  AtomicCmpXchgInst *cx = B.CreateAtomicCmpXchg(
      Flag, ConstantInt::get(I32g, 0), ConstantInt::get(I32g, 1), MaybeAlign(4),
      AtomicOrdering::AcquireRelease, AtomicOrdering::Acquire);
  B.CreateCondBr(B.CreateExtractValue(cx, 1), decbb, spin);
  B.SetInsertPoint(decbb);
  B.CreateCall(Helper, {dec, ConstantInt::get(I64, T.len), seedValue(B, Ctx, T.seed, ae)});
  StoreInst *stf = B.CreateStore(ConstantInt::get(I32g, 2), Flag);
  stf->setAtomic(AtomicOrdering::Release); stf->setAlignment(Align(4));
  B.CreateBr(done);
  B.SetInsertPoint(spin);
  LoadInst *s1 = B.CreateLoad(I32g, Flag);
  s1->setAtomic(AtomicOrdering::Acquire); s1->setAlignment(Align(4));
  B.CreateCondBr(B.CreateICmpEQ(s1, ConstantInt::get(I32g, 2)), done, spin);
  B.SetInsertPoint(done);
  B.CreateRet(dec);

  for (Use *U : uses) {
    auto *I = cast<Instruction>(U->getUser());
    Instruction *ip = I;
    if (auto *PN = dyn_cast<PHINode>(I))  // a phi operand must be ready in its incoming block
      ip = PN->getIncomingBlock(*U)->getTerminator();
    CallInst *c = CallInst::Create(Get->getFunctionType(), Get, {}, "", ip);
    U->set(c);
  }
  return true;
}

} // namespace

PreservedAnalyses StrEncPass::run(Module &M, ModuleAnalysisManager &) {
  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("strenc:" + M.getName()).str());
  bool cipher = std::getenv("RUSTCLOAK_STRENC_CIPHER") != nullptr;
  bool callsite = std::getenv("RUSTCLOAK_STRENC_CALLSITE") != nullptr;
  bool lazy = callsite || std::getenv("RUSTCLOAK_LAZY") != nullptr;  // call-site implies on-use
  std::vector<EncTarget> targets;

  for (GlobalVariable &G : M.globals()) {
    if (!G.hasInitializer() || !G.isConstant())
      continue;
    if (!(G.hasPrivateLinkage() || G.hasInternalLinkage()))
      continue;
    if (G.getName().starts_with("llvm."))
      continue;
    // Globals in the llvm.metadata section (e.g. the strings behind __attribute__((annotate(...))),
    // kept alive by @llvm.global.annotations but never emitted) must not be rewritten: encrypting
    // them adds a decrypt reference to a symbol codegen drops, giving "Undefined temporary symbol".
    if (G.getSection() == "llvm.metadata")
      continue;
    // C strings are a bare `[N x i8]`; Rust wraps them in a one-field struct
    // `<{ [N x i8] }>`. Unwrap the single-element aggregate to find the i8 array.
    Constant *init = G.getInitializer();
    auto *CDA = dyn_cast<ConstantDataArray>(init);
    StructType *wrapTy = nullptr;
    if (!CDA)
      if (auto *CS = dyn_cast<ConstantStruct>(init))
        if (CS->getNumOperands() == 1) {
          CDA = dyn_cast<ConstantDataArray>(CS->getOperand(0));
          wrapTy = CS->getType();
        }
    if (!CDA || !CDA->getElementType()->isIntegerTy(8))
      continue;
    // Referencing a global is always by pointer, so making it writable never breaks
    // another constant; the string is still reached through the same pointer.
    StringRef data = CDA->getRawDataValues();
    if (data.size() < 2 || data.size() > (1u << 16))
      continue;

    // Per-string seed: a full 32-bit odd value in cipher mode, else an odd key byte (low 8 bits).
    uint32_t seed = cipher ? ((uint32_t)gen() | 1u) : (uint32_t)(uint8_t)(gen() | 1u);
    std::vector<uint8_t> enc(data.begin(), data.end());
    xorKeystream(enc, seed, cipher);
    Constant *encArr = ConstantDataArray::get(Ctx, enc);
    G.setInitializer(wrapTy ? ConstantStruct::get(wrapTy, {encArr})
                            : encArr);
    G.setConstant(false);
    G.setUnnamedAddr(GlobalValue::UnnamedAddr::None); // the writable copy must not be merged
    targets.push_back({&G, seed, enc.size()});
  }
  if (targets.empty())
    return PreservedAnalyses::all();

  Function *Helper = getDecHelper(M, cipher);
  // RUSTCLOAK_ANTIEMU keys the decryption on a marker that a constructor sets before main, so a
  // deobfuscator that emulates the decryptor in isolation (without running constructors) recovers
  // garbage. Default off; it does not affect a real run.
  AntiEmu ae_storage, *ae = nullptr;
  Type *I32 = Type::getInt32Ty(Ctx);
  if (rustcloak::flagOn("RUSTCLOAK_STRENC_SELFKEY") && !targets.empty()) {
    // Derive the key marker at run time from a hash of the ciphertext, so static recovery must
    // execute the hash rather than read a constant (see emitComputedMarkerCtor). The anchor is the
    // first encrypted string; its ciphertext bytes are known here, so magic is computed to match.
    GlobalVariable *anchor = targets.front().G;
    uint64_t alen = targets.front().len;
    Constant *init = anchor->getInitializer();
    auto *cda = dyn_cast<ConstantDataArray>(init);
    if (!cda)
      if (auto *cs = dyn_cast<ConstantStruct>(init))
        cda = dyn_cast<ConstantDataArray>(cs->getOperand(0));
    // FNV-1a-32 over the ciphertext, matching the runtime hash. If the ciphertext is entirely zero,
    // ConstantStruct::get folds it to a ConstantAggregateZero (cda is then null) -- hash `alen` zero
    // bytes, which is exactly what the run-time loop reads from the all-zero anchor global.
    uint32_t magic = 2166136261u;
    if (cda) {
      for (unsigned char b : cda->getRawDataValues()) {
        magic ^= b;
        magic *= 16777619u;
      }
    } else {
      for (uint64_t i = 0; i < alen; i++)
        magic *= 16777619u;              // magic ^= 0 is a no-op
    }
    ae_storage.magic = magic;
    ae_storage.marker = new GlobalVariable(M, I32, /*isConstant=*/false, GlobalValue::InternalLinkage,
                                           ConstantInt::get(I32, 0), rustcloak::anon("mkv"));
    emitComputedMarkerCtor(M, ae_storage, anchor, alen);
    ae = &ae_storage;
  } else if (std::getenv("RUSTCLOAK_ANTIEMU")) {
    ae_storage.magic = (uint32_t)gen() | 1u;
    ae_storage.marker = new GlobalVariable(M, I32, /*isConstant=*/false, GlobalValue::InternalLinkage,
                                           ConstantInt::get(I32, 0), rustcloak::anon("mkv"));
    emitMarkerCtor(M, ae_storage);
    ae = &ae_storage;
  }
  // RUSTCLOAK_LAZY / RUSTCLOAK_STRENC_CALLSITE turn on on-demand decryption: each string decrypts
  // the first time it is used, not at startup. Default keeps the eager startup-constructor
  // behaviour, so a build is never affected unless a mode is explicitly requested.
  if (lazy) {
    std::vector<EncTarget> deferred;
    for (auto &T : targets)
      if (!makeLazy(M, Helper, T, ae, callsite))
        deferred.push_back(T);           // not lazifiable -> still encrypted, decrypted eagerly
    if (!deferred.empty())
      emitStartupCtor(M, Helper, deferred, ae);
  } else {
    emitStartupCtor(M, Helper, targets, ae);
  }
  return PreservedAnalyses::none();
}
