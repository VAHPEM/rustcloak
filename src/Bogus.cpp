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

// Build an always-true i1 that the optimizer cannot fold: (x*(x+1)) & 1 == 0.
Value *opaqueTrue(IRBuilder<> &B, Module &M) {
  Type *I32 = Type::getInt32Ty(M.getContext());
  Value *x = B.CreateLoad(I32, internalI32(M, rustcloak::anon("ox")), "");
  Value *xp1 = B.CreateAdd(x, ConstantInt::get(I32, 1));
  Value *prod = B.CreateMul(x, xp1);
  Value *lo = B.CreateAnd(prod, ConstantInt::get(I32, 1));
  return B.CreateICmpEQ(lo, ConstantInt::get(I32, 0), "");
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
  Value *cond = opaqueTrue(B, M);

  BasicBlock *bogus = BasicBlock::Create(M.getContext(), "", BB->getParent(), tail);
  IRBuilder<> BB2(bogus);
  // junk that cannot be trivially removed: a volatile store to a sink global.
  Type *I32 = Type::getInt32Ty(M.getContext());
  Value *x = BB2.CreateLoad(I32, internalI32(M, rustcloak::anon("ox")));
  Value *junk = BB2.CreateXor(BB2.CreateMul(x, ConstantInt::get(I32, (uint32_t)(gen() | 1))),
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
