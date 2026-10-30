// SPDX-License-Identifier: Apache-2.0
//===- Subst.cpp - instruction substitution --------------------------------===//
//
// Replaces simple integer arithmetic/logic operators with longer, equivalent expressions, so the
// obvious operation is no longer obvious. Two layers, both equivalence-preserving for wrapping
// (mod 2^w) integer arithmetic:
//
//   1. Mixed boolean-arithmetic (MBA) identities, SEVERAL per operator and chosen by seed so no one
//      pattern matches every rewrite -- e.g. a+b is any of (a^b)+2(a&b) / (a|b)+(a&b) / a-(~b)-1.
//   2. An invertible AFFINE (permutation-polynomial) encoding of add/sub: pick a per-op odd constant
//      A, compute in the encoded domain, decode with A's modular inverse --
//         a + b  =  A^{-1} * ( A*a + A*b )            (A odd => A invertible mod 2^w)
//      The optimizer run earlier cannot fold A*A^{-1} back to 1 because subst runs at OptimizerLast,
//      so the multiplies survive; a simplifier like arybo/SSPAM must recover the modular inverse.
//
// With RUSTCLOAK_SUBST_DEPTH=N (default 1) the rewrite is applied N times: operators created by one
// round are themselves eligible in the next, so expressions nest to depth N (capped, so it always
// terminates). Only scalar integers of width >= 2 are touched (the shl-by-1 in some identities is
// poison at width 1).
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallVector.h"

#include <cstdlib>
#include <vector>

using namespace llvm;

namespace {

// Modular inverse of an ODD `a` mod 2^bits (Newton's iteration mod 2^64, then masked). a*inv == 1.
static uint64_t modInverse(uint64_t a, unsigned bits) {
  uint64_t x = a;                       // correct mod 8 for any odd a
  for (int i = 0; i < 6; i++)           // each step doubles the correct bits: 8 -> >= 2^64
    x *= 2 - a * x;
  return bits >= 64 ? x : (x & ((1ull << bits) - 1));
}

// Replace one binary operator with an equivalent expression; returns the new value, or null to skip.
static Value *rewrite(BinaryOperator *bo, std::mt19937_64 &gen) {
  IRBuilder<> B(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type *ty = bo->getType();
  unsigned w = ty->getIntegerBitWidth();
  auto C = [&](uint64_t v) { return ConstantInt::get(ty, v); };

  switch (bo->getOpcode()) {
  case Instruction::Add:
    switch (gen() % 3) {
    case 0: return B.CreateAdd(B.CreateXor(a, b), B.CreateShl(B.CreateAnd(a, b), 1)); // (a^b)+2(a&b)
    case 1: return B.CreateAdd(B.CreateOr(a, b), B.CreateAnd(a, b));                  // (a|b)+(a&b)
    default: {                                                                       // affine encode
      uint64_t A = (gen() | 1u); if (w < 64) A &= (1ull << w) - 1; A |= 1;
      uint64_t Ai = modInverse(A, w);
      return B.CreateMul(B.CreateAdd(B.CreateMul(a, C(A)), B.CreateMul(b, C(A))), C(Ai));
    }
    }
  case Instruction::Sub:
    switch (gen() % 3) {
    case 0: return B.CreateSub(B.CreateXor(a, b), B.CreateShl(B.CreateAnd(B.CreateNot(a), b), 1)); // (a^b)-2(~a&b)
    case 1: return B.CreateSub(B.CreateAnd(a, B.CreateNot(b)), B.CreateAnd(B.CreateNot(a), b));    // (a&~b)-(~a&b)
    default: {                                                                                    // affine encode
      uint64_t A = (gen() | 1u); if (w < 64) A &= (1ull << w) - 1; A |= 1;
      uint64_t Ai = modInverse(A, w);
      return B.CreateMul(B.CreateSub(B.CreateMul(a, C(A)), B.CreateMul(b, C(A))), C(Ai));
    }
    }
  case Instruction::Xor:
    switch (gen() % 2) {
    case 0: return B.CreateSub(B.CreateOr(a, b), B.CreateAnd(a, b));                  // (a|b)-(a&b)
    default: return B.CreateAnd(B.CreateOr(a, b), B.CreateNot(B.CreateAnd(a, b)));    // (a|b)&~(a&b)
    }
  case Instruction::And:
    switch (gen() % 2) {
    case 0: return B.CreateSub(B.CreateOr(a, b), B.CreateXor(a, b));                  // (a|b)-(a^b)
    default: return B.CreateAnd(a, B.CreateNot(B.CreateAnd(a, B.CreateNot(b))));      // a & ~(a&~b)
    }
  case Instruction::Or:
    switch (gen() % 2) {
    case 0: return B.CreateAdd(B.CreateAnd(a, b), B.CreateXor(a, b));                 // (a&b)+(a^b)
    default: return B.CreateSub(B.CreateAdd(a, b), B.CreateAnd(a, b));                // a+b-(a&b)
    }
  default:
    return nullptr;
  }
}

// Wrap v in an invertible xor-shift permutation round-trip: encode e = v ^ (v<<s), then decode with
// the doubling inverse of (I + L^s) over GF(2)^w. decode(encode(v)) == v for EVERY v at width w --
// (I + L^s) is unipotent (L = 1-bit left shift is nilpotent, L^w = 0); its inverse is the geometric
// series I + L^s + L^2s + ..., and the product form prod_i (I + L^(2^i s)) telescopes to it with all
// cross terms cancelling in characteristic 2. LLVM does not reason about GF(2) linear algebra, so it
// cannot fold the round-trip back to v, yet the value is provably unchanged: a permutation-polynomial
// MBA that never miscompiles. (Exhaustively verified for w in {8,16}; see test/mba_perm.c.)
static Value *permuteWrap(IRBuilder<> &B, Value *v, unsigned s) {
  Type *ty = v->getType();
  unsigned w = ty->getIntegerBitWidth();
  Value *x = B.CreateXor(v, B.CreateShl(v, ConstantInt::get(ty, s)));   // encode: (I + L^s) v
  for (unsigned k = s; k < w; k *= 2)                                    // decode: product doubling
    x = B.CreateXor(x, B.CreateShl(x, ConstantInt::get(ty, k)));
  return x;                                                              // == v for all inputs
}
} // namespace

PreservedAnalyses SubstPass::run(Function &F, FunctionAnalysisManager &) {
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  auto gen = rustcloak::rng(("subst:" + F.getName()).str());

  int depth = rustcloak::hardenPreset() ? 2 : 1;       // the strong preset nests MBA to depth 2
  if (const char *e = std::getenv("RUSTCLOAK_SUBST_DEPTH")) {
    depth = std::atoi(e);
    depth = depth < 1 ? 1 : (depth > 4 ? 4 : depth);   // bounded so expansion always terminates
  }

  const size_t maxInsts = 20000;
  bool changed = false;
  for (int round = 0; round < depth; round++) {
    size_t n = 0;
    for (BasicBlock &BB : F)
      n += BB.size();
    if (n > maxInsts)
      break;  // Stop expansion of very large functions.
    std::vector<BinaryOperator *> ops;     // snapshot this round's operators (not the ones we create)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *bo = dyn_cast<BinaryOperator>(&I))
          // width >= 2: the shl-by-1 used in some identities is poison at bit width 1.
          if (bo->getType()->isIntegerTy() && bo->getType()->getIntegerBitWidth() >= 2)
            ops.push_back(bo);

    bool any = false;
    for (BinaryOperator *bo : ops) {
      if ((gen() & 3u) == 0u)              // leave ~1 in 4 alone, for variety
        continue;
      if (Value *r = rewrite(bo, gen)) {
        bo->replaceAllUsesWith(r);
        bo->eraseFromParent();
        any = changed = true;
      }
    }
    if (!any)
      break;                               // nothing left to expand
  }
  // Permutation-polynomial MBA (RUSTCLOAK_MBA_PERM): wrap a random subset of integer results in an
  // invertible xor-shift round-trip (see permuteWrap). Default off; it compounds with the MBA above
  // and, unlike constant-coefficient affine encoding, the optimizer cannot fold it away.
  if (std::getenv("RUSTCLOAK_MBA_PERM")) {
    size_t budget = 0;
    for (BasicBlock &BB : F)
      budget += BB.size();
    size_t cap = maxInsts > budget ? (maxInsts - budget) / 8 : 0;   // respect the per-function ceiling
    std::vector<BinaryOperator *> wrap;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *bo = dyn_cast<BinaryOperator>(&I))
          if (bo->getType()->isIntegerTy()) {
            unsigned w = bo->getType()->getIntegerBitWidth();
            if (w >= 2 && w <= 64)
              wrap.push_back(bo);
          }
    for (BinaryOperator *I : wrap) {
      if (!cap)
        break;
      if ((gen() & 1u) == 0u)              // wrap about half, for variety
        continue;
      SmallVector<Use *, 8> uses;
      for (Use &U : I->uses())
        uses.push_back(&U);
      if (uses.empty())
        continue;
      unsigned w = I->getType()->getIntegerBitWidth();
      unsigned sft = 1u + (unsigned)(gen() % (w - 1));   // 1 <= s <= w-1, so every shift amount < w
      IRBuilder<> B(I->getNextNode());
      Value *wv = permuteWrap(B, I, sft);
      for (Use *U : uses)
        U->set(wv);                        // redirect only PRE-EXISTING uses; the encode keeps using I
      changed = true;
      --cap;
    }
  }
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
