// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Commercial
//===- License.cpp - license key gate (RUSTCLOAK_LICENSE) -------------------===//
//
// Build with RUSTCLOAK_LICENSE=<hex> set to the FNV-1a-64 of the valid license key. A constructor
// reads the RC_KEY environment variable at run time, FNV-hashes it, and folds (hash ^ expected) into
// a key `lic_k` -- 0 iff the key is correct. A random subset of integer constants across the module
// are keyed as `C ^ trunc(lic_k)`: with the right RC_KEY the program behaves exactly as baseline;
// with a wrong or missing key the constants corrupt and it misbehaves. The response is branch-free
// (like the anti-tamper check) and `expected` is a compile-time constant folded into the key, so
// there is no visible compare-the-license-and-jump for an analyst to patch out. (To bind to hardware
// instead of an env var, have the program feed a machine id into RC_KEY before main.)
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdlib>
#include <utility>
#include <vector>

using namespace llvm;

static const uint64_t LIC_FNV_OFFSET = 0xcbf29ce484222325ull;
static const uint64_t LIC_FNV_PRIME  = 0x100000001b3ull;

PreservedAnalyses LicensePass::run(Module &M, ModuleAnalysisManager &) {
  const char *env = std::getenv("RUSTCLOAK_LICENSE");
  if (!env)
    return PreservedAnalyses::all();
  char *end = nullptr;
  uint64_t expected = std::strtoull(env, &end, 0);
  if (end == env)
    return PreservedAnalyses::all();

  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("license:" + M.getName()).str());
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::get(Ctx, 0);

  // getenv declaration (ptr getenv(ptr)) + the "RC_KEY" name string.
  FunctionCallee getenvFn = M.getOrInsertFunction("getenv", FunctionType::get(Ptr, {Ptr}, false));
  Constant *keyName = ConstantDataArray::getString(Ctx, "RC_KEY", true);
  auto *keyNameG = new GlobalVariable(M, keyName->getType(), true, GlobalValue::PrivateLinkage,
                                      keyName, rustcloak::anon("ln"));

  auto *lic_k = new GlobalVariable(M, I64, false, GlobalValue::InternalLinkage,
                                   ConstantInt::get(I64, 0), rustcloak::anon("lk"));

  // ctor: lic_k = FNV(getenv("RC_KEY")) ^ expected
  Function *ctor = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                    GlobalValue::InternalLinkage, rustcloak::anon("lc"), M);
  BasicBlock *entry = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *li = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *cnd = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *bod = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *don = BasicBlock::Create(Ctx, "", ctor);
  IRBuilder<> B(entry);
  AllocaInst *h = B.CreateAlloca(I64);
  AllocaInst *pp = B.CreateAlloca(Ptr);
  B.CreateStore(ConstantInt::get(I64, LIC_FNV_OFFSET), h);
  Value *envp = B.CreateCall(getenvFn, {keyNameG});
  B.CreateCondBr(B.CreateICmpNE(envp, ConstantPointerNull::get(cast<PointerType>(Ptr))), li, don);
  B.SetInsertPoint(li);
  B.CreateStore(envp, pp);
  B.CreateBr(cnd);
  B.SetInsertPoint(cnd);
  Value *p = B.CreateLoad(Ptr, pp);
  Value *c = B.CreateLoad(I8, p);
  B.CreateCondBr(B.CreateICmpNE(c, ConstantInt::get(I8, 0)), bod, don);
  B.SetInsertPoint(bod);
  Value *hv = B.CreateLoad(I64, h);
  hv = B.CreateMul(B.CreateXor(hv, B.CreateZExt(c, I64)), ConstantInt::get(I64, LIC_FNV_PRIME));
  B.CreateStore(hv, h);
  B.CreateStore(B.CreateGEP(I8, p, ConstantInt::get(I64, 1)), pp);
  B.CreateBr(cnd);
  B.SetInsertPoint(don);
  Value *delta = B.CreateXor(B.CreateLoad(I64, h), ConstantInt::get(I64, expected));
  StoreInst *stk = B.CreateStore(delta, lic_k);
  stk->setVolatile(true);
  B.CreateRetVoid();
  appendToGlobalCtors(M, ctor, 0);

  // key a subset of integer constants with lic_k (0 when the key is correct -> identity).
  for (Function &F : M) {
    if (F.isDeclaration() || &F == ctor || F.getEntryBlock().empty())
      continue;
    IRBuilder<> BK(&*F.getEntryBlock().getFirstInsertionPt());
    LoadInst *kl = BK.CreateLoad(I64, lic_k);
    kl->setVolatile(true);
    std::vector<std::pair<Instruction *, unsigned>> work;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (&I == kl)
          continue;
        bool ok = isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<StoreInst>(I) ||
                  isa<ReturnInst>(I) || isa<SelectInst>(I);
        if (!ok)
          continue;
        for (unsigned k = 0; k < I.getNumOperands(); k++)
          if (auto *cst = dyn_cast<ConstantInt>(I.getOperand(k)))
            if (cst->getType()->isIntegerTy() && cst->getType()->getIntegerBitWidth() <= 64)
              work.push_back({&I, k});
      }
    for (auto &w : work) {
      if ((gen() & 3u) == 0u)              // key ~3 in 4
        continue;
      Instruction *I = w.first;
      auto *cst = cast<ConstantInt>(I->getOperand(w.second));
      Type *t = cst->getType();
      IRBuilder<> B2(I);
      Value *kt = t->getIntegerBitWidth() == 64 ? (Value *)kl : B2.CreateTrunc(kl, t);
      I->setOperand(w.second, B2.CreateXor(cst, kt));
    }
  }
  return PreservedAnalyses::none();
}
