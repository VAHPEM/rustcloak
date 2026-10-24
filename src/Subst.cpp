//===- Subst.cpp - instruction substitution --------------------------------===//
//
// Replaces simple integer arithmetic/logic operators with longer, equivalent
// expressions, so the obvious operation is no longer obvious:
//
//   a + b  ->  a - (-b)
//   a - b  ->  a + (-b)
//   a ^ b  ->  (a & ~b) | (~a & b)
//   a & b  ->  ~(~a | ~b)
//   a | b  ->  ~(~a & ~b)
//
// Each eligible scalar-integer operator is rewritten with some probability. Only the
// operators present before the pass are rewritten (the replacements are not recursed
// into), so the transform terminates.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <vector>

using namespace llvm;

PreservedAnalyses SubstPass::run(Function &F, FunctionAnalysisManager &) {
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  auto gen = rustcloak::rng(("subst:" + F.getName()).str());

  std::vector<BinaryOperator *> ops;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *bo = dyn_cast<BinaryOperator>(&I))
        if (bo->getType()->isIntegerTy())
          ops.push_back(bo);

  bool changed = false;
  for (BinaryOperator *bo : ops) {
    if ((gen() & 3u) == 0u)       // leave ~1 in 4 alone, for variety
      continue;
    IRBuilder<> B(bo);
    Value *a = bo->getOperand(0), *b = bo->getOperand(1), *r = nullptr;
    switch (bo->getOpcode()) {
    case Instruction::Add:
      r = B.CreateSub(a, B.CreateNeg(b));
      break;
    case Instruction::Sub:
      r = B.CreateAdd(a, B.CreateNeg(b));
      break;
    case Instruction::Xor:
      r = B.CreateOr(B.CreateAnd(a, B.CreateNot(b)),
                     B.CreateAnd(B.CreateNot(a), b));
      break;
    case Instruction::And:
      r = B.CreateNot(B.CreateOr(B.CreateNot(a), B.CreateNot(b)));
      break;
    case Instruction::Or:
      r = B.CreateNot(B.CreateAnd(B.CreateNot(a), B.CreateNot(b)));
      break;
    default:
      continue;
    }
    bo->replaceAllUsesWith(r);
    bo->eraseFromParent();
    changed = true;
  }
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
