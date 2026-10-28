//===- ConstEnc.cpp - integer constant obfuscation -------------------------===//
//
// Hides integer literal operands: a constant C is replaced by `C ^ z`, where `z` is an opaque ZERO
// computed from a real in-scope value -- `(x*(x+1)) & 1`, which is 0 for every x because two
// consecutive integers have opposite parity. Because x is actual program data (a function
// argument), the optimizer cannot fold z to 0 (KnownBits does not track the consecutive-integer
// correlation), so the literal no longer appears in the code, yet the runtime value is unchanged.
//
// Opt-in via RUSTCLOAK_CONSTENC. Only operands where an arbitrary Value is legal are touched
// (binary ops, comparisons, stores, returns, selects); getelementptr indices, switch cases, phi
// incomings, and call arguments (which may be `immarg`) are left alone.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <cstdlib>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

// An opaque zero of type `ty`, from a dominating value `xBase` cast to `ty`: (x*(x+1)) & 1 == 0.
Value *opaqueZero(IRBuilder<> &B, Value *xBase, Type *ty) {
  Value *x = xBase;
  unsigned w = ty->getIntegerBitWidth(), xw = x->getType()->getIntegerBitWidth();
  if (xw > w)
    x = B.CreateTrunc(x, ty);
  else if (xw < w)
    x = B.CreateZExt(x, ty);
  Value *one = ConstantInt::get(ty, 1);
  return B.CreateAnd(B.CreateMul(x, B.CreateAdd(x, one)), one);
}

} // namespace

PreservedAnalyses ConstEncPass::run(Function &F, FunctionAnalysisManager &) {
  if (!std::getenv("RUSTCLOAK_CONSTENC") || F.isDeclaration())
    return PreservedAnalyses::all();

  // A real, dominating integer seed: an integer function argument (arguments dominate everything).
  Argument *seed = nullptr;
  for (Argument &A : F.args())
    if (A.getType()->isIntegerTy()) {
      seed = &A;
      break;
    }
  if (!seed)
    return PreservedAnalyses::all();

  auto gen = rustcloak::rng(("constenc:" + F.getName()).str());

  // Collect (instruction, operand index) pairs whose operand is an integer literal we may replace.
  std::vector<std::pair<Instruction *, unsigned>> work;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      bool ok = isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<StoreInst>(I) ||
                isa<ReturnInst>(I) || isa<SelectInst>(I);
      if (!ok)
        continue;
      for (unsigned k = 0; k < I.getNumOperands(); k++)
        if (auto *ci = dyn_cast<ConstantInt>(I.getOperand(k)))
          if (ci->getType()->isIntegerTy() && ci->getType()->getIntegerBitWidth() <= 64)
            work.push_back({&I, k});
    }

  bool changed = false;
  for (auto &w : work) {
    if ((gen() & 3u) == 0u)              // hide ~3 in 4
      continue;
    Instruction *I = w.first;
    auto *ci = cast<ConstantInt>(I->getOperand(w.second));
    IRBuilder<> B(I);
    Value *hidden = B.CreateXor(ci, opaqueZero(B, seed, ci->getType()));
    I->setOperand(w.second, hidden);
    changed = true;
  }
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
