//===- Bogus.cpp - bogus control flow + opaque predicates ------------------===//
//
// Splits blocks and guards the real continuation with an *opaque predicate* -- a
// condition that is always true but that the optimizer cannot fold, because it is
// computed from a non-constant global. Each guarded block gains a fake alternate
// path (never taken) so the control-flow graph is cluttered with branches a reader
// must reason through.
//
// The opaque predicate used is  (x*(x+1)) & 1 == 0, which is always true because the
// product of two consecutive integers is even. `x` is a module-internal, non-constant
// global, so neither the optimizer nor a static reader can assume its value.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <vector>

using namespace llvm;

namespace {

GlobalVariable *internalI32(Module &M, StringRef name) {
  if (auto *G = M.getGlobalVariable(name, /*AllowInternal=*/true))
    return G;
  Type *I32 = Type::getInt32Ty(M.getContext());
  auto *G = new GlobalVariable(M, I32, /*isConstant=*/false,
                               GlobalValue::InternalLinkage,
                               ConstantInt::get(I32, 0), name);
  return G;
}

// An always-true i1 computed from a REAL in-scope 32-bit value x. Because x is actual program data
// (not a constant), the optimizer cannot fold the predicate -- it does not know x's value, and the
// relevant invariants (e.g. x and x+1 have opposite parity) are correlations KnownBits does not
// track -- and an analyst must reason about the function's own dataflow to see it is always true.
// Several families are mixed per block (seed-chosen) so no single shape can be pattern-matched;
// each reduces to a parity identity true for every 32-bit x (verified with z3).
Value *opaqueTrueFrom(IRBuilder<> &B, Value *x, Value *y, std::mt19937_64 &gen) {
  Value *zero = B.getInt32(0), *one = B.getInt32(1);
  // Two-variable families when a second independent in-scope value exists: these depend on BOTH x
  // and y, so a solver cannot reduce them to a single-variable parity identity. Each is always true
  // for all 32-bit x,y, built on the x*(x+1)-is-even trick that survives -O2 (z3-checked).
  if (y) {
    switch (gen() % 3) {
    case 0: {                             // (x*(x+1) + y*(y+1)) & 1 == 0  (sum of two evens)
      Value *px = B.CreateMul(x, B.CreateAdd(x, one));
      Value *py = B.CreateMul(y, B.CreateAdd(y, one));
      return B.CreateICmpEQ(B.CreateAnd(B.CreateAdd(px, py), one), zero, "");
    }
    case 1: {                             // (y * x*(x+1)) & 1 == 0  (y times an even)
      Value *px = B.CreateMul(x, B.CreateAdd(x, one));
      return B.CreateICmpEQ(B.CreateAnd(B.CreateMul(y, px), one), zero, "");
    }
    default: {                            // low bit of x*(x+1) equals low bit of y*(y+1) (both 0)
      Value *px = B.CreateAnd(B.CreateMul(x, B.CreateAdd(x, one)), one);
      Value *py = B.CreateAnd(B.CreateMul(y, B.CreateAdd(y, one)), one);
      return B.CreateICmpEQ(px, py, "");
    }
    }
  }
  switch (gen() % 5) {
  case 0: {                               // (x*(x+1)) & 1 == 0
    Value *p = B.CreateMul(x, B.CreateAdd(x, one));
    return B.CreateICmpEQ(B.CreateAnd(p, one), zero, "");
  }
  case 1: {                               // (x*x + x) & 1 == 0
    Value *p = B.CreateAdd(B.CreateMul(x, x), x);
    return B.CreateICmpEQ(B.CreateAnd(p, one), zero, "");
  }
  case 2: {                               // ((x*x) ^ x) & 1 == 0
    Value *p = B.CreateXor(B.CreateMul(x, x), x);
    return B.CreateICmpEQ(B.CreateAnd(p, one), zero, "");
  }
  case 3: {                               // consecutive ints differ in the low bit: (x ^ (x+1)) & 1 == 1
    Value *p = B.CreateXor(x, B.CreateAdd(x, one));
    return B.CreateICmpEQ(B.CreateAnd(p, one), one, "");
  }
  default: {                              // x*(x-1) is even (two consecutive integers)
    Value *p = B.CreateMul(x, B.CreateSub(x, one));
    return B.CreateICmpEQ(B.CreateAnd(p, one), zero, "");
  }
  }
}

// A real, dominating i32 to seed the predicate: an integer function argument (arguments dominate
// every instruction in the function), narrowed/widened to i32. Returns nullptr when the function
// has no integer argument, so the caller can fall back to the module-internal global.
Value *realSeed(IRBuilder<> &B, Function *F) {
  for (Argument &A : F->args())
    if (A.getType()->isIntegerTy()) {
      unsigned w = A.getType()->getIntegerBitWidth();
      if (w == 32) return &A;
      if (w > 32)  return B.CreateTrunc(&A, B.getInt32Ty());
      return B.CreateZExt(&A, B.getInt32Ty());
    }
  return nullptr;
}

// An integer value (width >= 2) defined in `head` or an argument, and USED in `tail`. Such a value
// can be routed through a diamond -- its uses in the tail redirected to a PHI -- so an injected arm
// produces a value that genuinely feeds the program's dataflow (not a dead sink). null if none.
Value *liveIntUsedIn(BasicBlock *head, BasicBlock *tail) {
  for (Instruction &I : *tail)
    for (Value *op : I.operands()) {
      if (auto *vi = dyn_cast<Instruction>(op)) {
        if (vi->getParent() == head && vi->getType()->isIntegerTy() &&
            vi->getType()->getIntegerBitWidth() >= 2)
          return vi;
      } else if (auto *arg = dyn_cast<Argument>(op)) {
        if (arg->getType()->isIntegerTy() && arg->getType()->getIntegerBitWidth() >= 2)
          return arg;
      }
    }
  return nullptr;
}

// A SECOND real, dominating i32 distinct from realSeed's (the second integer argument), for the
// two-variable opaque predicates; nullptr when the function has fewer than two integer arguments.
Value *realSeed2(IRBuilder<> &B, Function *F) {
  int seen = 0;
  for (Argument &A : F->args())
    if (A.getType()->isIntegerTy()) {
      if (seen++ == 0) continue;          // skip the first (realSeed's)
      unsigned w = A.getType()->getIntegerBitWidth();
      if (w == 32) return &A;
      if (w > 32)  return B.CreateTrunc(&A, B.getInt32Ty());
      return B.CreateZExt(&A, B.getInt32Ty());
    }
  return nullptr;
}

bool bogusBlock(BasicBlock *BB, Module &M, std::mt19937_64 &gen) {
  if (BB->isEHPad() || isa<PHINode>(BB->getTerminator()))
    return false;
  // choose a split point: a non-PHI instruction before the terminator
  Instruction *split = BB->getFirstNonPHI();
  if (!split || split == BB->getTerminator())
    return false;
  // advance a little into the block so both halves have content
  unsigned skip = gen() % 3;
  for (unsigned i = 0; i < skip && split->getNextNode() &&
                       split->getNextNode() != BB->getTerminator();
       i++)
    split = split->getNextNode();
  if (split == BB->getTerminator())
    return false;

  BasicBlock *tail = BB->splitBasicBlock(split, "");
  // BB now ends in `br tail`; replace with an opaque-guarded branch to tail or bogus.
  Instruction *term = BB->getTerminator();
  IRBuilder<> B(term);
  // Seed the opaque predicate from a real in-scope value when one exists (unfoldable, tied to the
  // function's own data); otherwise fall back to the module-internal global.
  Value *x = realSeed(B, BB->getParent());
  Value *y = nullptr;
  if (!x)
    x = B.CreateLoad(Type::getInt32Ty(M.getContext()), internalI32(M, rustcloak::anon("ox")), "");
  else
    y = realSeed2(B, BB->getParent());   // a second argument -> two-variable predicate when present
  Value *cond = opaqueTrueFrom(B, x, y, gen);

  Type *I32 = Type::getInt32Ty(M.getContext());
  BasicBlock *bogus = BasicBlock::Create(M.getContext(), "", BB->getParent(), tail);
  IRBuilder<> BB2(bogus);
  // A volatile READ of module state anchors the bogus block (a real side effect, so it is not
  // speculated into a select and the CFG stays cluttered) -- not a volatile store to a dedicated
  // sink, which is a one-line grep/YARA signature.
  LoadInst *rd = BB2.CreateLoad(I32, internalI32(M, rustcloak::anon("ox")));
  rd->setVolatile(true);

  // Prefer REALISTIC junk: compute a hash/mix-shaped value from a live in-scope value and feed it
  // back into the flow through a PHI the tail uses, so the bogus arm looks like ordinary program
  // computation rather than an obvious dead store. (The arm never executes -- the predicate is
  // always true -- so the value is free to differ from the real one.)
  Value *v = liveIntUsedIn(BB, tail);
  if (v) {
    Type *ty = v->getType();
    auto C = [&](uint64_t k) { return ConstantInt::get(ty, k); };
    Value *anchor = BB2.CreateZExtOrTrunc(BB2.CreateAnd(rd, ConstantInt::get(I32, 0)), ty); // == 0
    Value *vj = BB2.CreateXor(BB2.CreateMul(v, C(gen() | 1u)), BB2.CreateLShr(v, C(3)));
    vj = BB2.CreateAdd(BB2.CreateAdd(vj, C(gen())), anchor);  // hash-step shape, anchored
    BB2.CreateBr(tail);
    BranchInst::Create(tail, bogus, cond, term);
    term->eraseFromParent();
    // route it back: tail uses of v now read a PHI fed by the real value (taken edge) and the junk.
    PHINode *vp = PHINode::Create(ty, 2, "", &*tail->getFirstInsertionPt());
    vp->addIncoming(v, BB);
    vp->addIncoming(vj, bogus);
    for (Instruction &I : *tail)
      if (&I != vp)
        for (Use &U : I.operands())
          if (U.get() == v)
            U.set(vp);
    return true;
  }

  // Fallback (no routable value in scope): a store-free junk computation anchored by the volatile
  // read, into a module-internal global that looks like ordinary state -- still no dedicated sink.
  Value *junk = BB2.CreateXor(BB2.CreateMul(rd, ConstantInt::get(I32, (uint32_t)(gen() | 1))),
                              ConstantInt::get(I32, (uint32_t)gen()));
  BB2.CreateStore(junk, internalI32(M, rustcloak::anon("st")));
  BB2.CreateBr(tail);
  BranchInst::Create(tail, bogus, cond, term);
  term->eraseFromParent();
  return true;
}

// A TWO-WAY opaque predicate (RUSTCLOAK_BOGUS_TWOWAY). The one-way form above guards the real path
// with an always-true predicate and a dead bogus block -- which `simplifycfg` can prune once it
// proves the predicate constant. This form has NO dead branch: it splits the block and routes a live
// integer value through a diamond whose two arms recompute that value by DIFFERENT (equivalent)
// expressions, selected by a genuinely data-dependent predicate on a live value. Both arms are
// reachable and both feed a PHI the tail then uses, so neither can be folded away as dead, and the
// branch encodes a real (if irrelevant) runtime decision rather than a constant.
bool twoWayBlock(BasicBlock *BB, Module &M, std::mt19937_64 &gen) {
  if (BB->isEHPad())
    return false;
  Instruction *split = BB->getFirstNonPHI();
  if (!split || split == BB->getTerminator())
    return false;
  unsigned skip = gen() % 3;
  for (unsigned i = 0; i < skip && split->getNextNode() &&
                       split->getNextNode() != BB->getTerminator();
       i++)
    split = split->getNextNode();
  if (split == BB->getTerminator())
    return false;

  BasicBlock *tail = BB->splitBasicBlock(split, "");
  // A live integer value defined in the head (or an argument) and used in the tail: routing it
  // through the diamond gives the arms a real, used result, so nothing is dead code.
  Value *v = liveIntUsedIn(BB, tail);
  if (!v)
    return false;                      // nothing to route -> leave the plain split (still correct)

  LLVMContext &Ctx = M.getContext();
  Type *ty = v->getType();
  Function *F = BB->getParent();
  BasicBlock *A = BasicBlock::Create(Ctx, "", F, tail);
  BasicBlock *Bb = BasicBlock::Create(Ctx, "", F, tail);
  BasicBlock *join = BasicBlock::Create(Ctx, "", F, tail);

  Instruction *term = BB->getTerminator();   // the `br tail` splitBasicBlock created
  IRBuilder<> H(term);
  // genuinely data-dependent selector (low bit of a live value): both arms are correct, so which one
  // runs does not matter -- but it is not a constant, so neither arm is statically dead.
  Value *sel = H.CreateICmpNE(H.CreateAnd(v, ConstantInt::get(ty, 1)), ConstantInt::get(ty, 0));
  BranchInst::Create(A, Bb, sel, term);
  term->eraseFromParent();

  // Each arm reads a module-internal global through a VOLATILE load and folds `& 0` of it into its
  // result: the value is always 0 (so the arm still computes v), but the volatile read is a real
  // side effect, so the optimizer will not speculate the arm and collapse the diamond into a plain
  // `select` -- the two-way branch survives. A volatile *read* of program data is also far less of a
  // signature than a volatile store to a dedicated sink.
  Type *I32 = Type::getInt32Ty(Ctx);
  uint64_t K1 = gen(), K2 = gen() | 1u;
  auto zeroFrom = [&](IRBuilder<> &BX) {      // == 0, but anchored to a volatile read
    LoadInst *l = BX.CreateLoad(I32, internalI32(M, rustcloak::anon("ox")));
    l->setVolatile(true);
    return BX.CreateZExtOrTrunc(BX.CreateAnd(l, ConstantInt::get(I32, 0)), ty);
  };
  IRBuilder<> BA(A);                          // vA = ((v + K1) - K1) + 0  == v
  Value *vA = BA.CreateAdd(BA.CreateSub(BA.CreateAdd(v, ConstantInt::get(ty, K1)),
                                        ConstantInt::get(ty, K1)), zeroFrom(BA));
  BA.CreateBr(join);
  IRBuilder<> BB2(Bb);                        // vB = ((v ^ K2) ^ K2) + 0  == v
  Value *vB = BB2.CreateAdd(BB2.CreateXor(BB2.CreateXor(v, ConstantInt::get(ty, K2)),
                                          ConstantInt::get(ty, K2)), zeroFrom(BB2));
  BB2.CreateBr(join);
  IRBuilder<> BJ(join);
  PHINode *vp = BJ.CreatePHI(ty, 2);
  vp->addIncoming(vA, A);
  vp->addIncoming(vB, Bb);
  BJ.CreateBr(tail);

  // Redirect the tail's uses of v to the PHI (join dominates tail, so this is valid SSA). Uses of v
  // in the head / arms keep the original value.
  for (Instruction &I : *tail)
    for (Use &U : I.operands())
      if (U.get() == v)
        U.set(vp);
  return true;
}

} // namespace

PreservedAnalyses BogusPass::run(Function &F, FunctionAnalysisManager &) {
  if (F.isDeclaration() || F.size() == 0)
    return PreservedAnalyses::all();
  Module &M = *F.getParent();
  auto gen = rustcloak::rng(("bogus:" + F.getName()).str());

  std::vector<BasicBlock *> blocks;        // snapshot: don't process blocks we create
  for (BasicBlock &BB : F)
    blocks.push_back(&BB);

  bool twoway = rustcloak::flagOn("RUSTCLOAK_BOGUS_TWOWAY");
  bool changed = false;
  for (BasicBlock *BB : blocks) {
    if ((gen() & 1u) == 0u)               // guard about half the blocks
      continue;
    changed |= twoway ? twoWayBlock(BB, M, gen) : bogusBlock(BB, M, gen);
  }
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
