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
Value *opaqueTrueFrom(IRBuilder<> &B, Value *x, std::mt19937_64 &gen) {
  Value *zero = B.getInt32(0), *one = B.getInt32(1);
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
  if (!x)
    x = B.CreateLoad(Type::getInt32Ty(M.getContext()), internalI32(M, rustcloak::anon("ox")), "");
  Value *cond = opaqueTrueFrom(B, x, gen);

  BasicBlock *bogus = BasicBlock::Create(M.getContext(), "", BB->getParent(), tail);
  IRBuilder<> BB2(bogus);
  // junk that cannot be trivially removed: a volatile store to a sink global.
  Type *I32 = Type::getInt32Ty(M.getContext());
  Value *jx = BB2.CreateLoad(I32, internalI32(M, rustcloak::anon("ox")));
  Value *junk = BB2.CreateXor(BB2.CreateMul(jx, ConstantInt::get(I32, (uint32_t)(gen() | 1))),
                              ConstantInt::get(I32, (uint32_t)gen()));
  BB2.CreateStore(junk, internalI32(M, rustcloak::anon("sink")))->setVolatile(true);
  BB2.CreateBr(tail);               // tail has no PHIs (split mid-block), so this is safe

  BranchInst::Create(tail, bogus, cond, term);
  term->eraseFromParent();
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

  bool changed = false;
  for (BasicBlock *BB : blocks) {
    if ((gen() & 1u) == 0u)               // guard about half the blocks
      continue;
    changed |= bogusBlock(BB, M, gen);
  }
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
