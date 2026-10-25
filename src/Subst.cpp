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
    // Mixed boolean-arithmetic (MBA) identities, each proven equivalent for all inputs with z3
    // (deobf_expr.py). These mix arithmetic and bitwise ops so the operation is far less obvious
    // than the earlier a-(-b) style rewrites, and resist simple pattern reversal.
    switch (bo->getOpcode()) {
    case Instruction::Add:   // a + b = (a ^ b) + 2*(a & b)
      r = B.CreateAdd(B.CreateXor(a, b), B.CreateShl(B.CreateAnd(a, b), 1));
      break;
    case Instruction::Sub:   // a - b = (a ^ b) - 2*(~a & b)
      r = B.CreateSub(B.CreateXor(a, b),
                      B.CreateShl(B.CreateAnd(B.CreateNot(a), b), 1));
      break;
    case Instruction::Xor:   // a ^ b = (a | b) - (a & b)
      r = B.CreateSub(B.CreateOr(a, b), B.CreateAnd(a, b));
      break;
    case Instruction::And:   // a & b = (a | b) - (a ^ b)
      r = B.CreateSub(B.CreateOr(a, b), B.CreateXor(a, b));
      break;
    case Instruction::Or:    // a | b = (a & b) + (a ^ b)
      r = B.CreateAdd(B.CreateAnd(a, b), B.CreateXor(a, b));
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
