//===- AntiTamper.cpp - .text (section) self-integrity ----------------------===//
//
// RUSTCLOAK_ANTITAMPER. Every defined function is placed in a custom, C-identifier-named section so
// the linker brackets it with __start_<sec>/__stop_<sec>; a constructor FNV-1a-hashes that section
// at run time and folds (hash ^ expected) into an i64 key `rc_k` -- 0 when the code is intact. A
// random subset of integer constants across the module are then keyed as `C ^ trunc(rc_k)`: intact
// -> rc_k==0 -> every constant unchanged (behaviour identical to baseline); a single patched byte in
// the protected section makes the hash diverge, rc_k becomes nonzero, and those constants silently
// corrupt. The response is BRANCH-FREE (nothing for an analyst to NOP out) and `expected` is read
// through a volatile load, so the optimizer cannot pre-compute the delta.
//
// `expected` is filled AFTER linking by tools/antitamper_patch.py, which finds the descriptor global
// by a fixed 8-byte magic, reads the protected section's name from it, hashes that section on disk
// (identical to the in-memory bytes for a PIE code section), and writes the hash into `expected`.
// An ANTITAMPER build therefore REQUIRES running that tool once on the linked binary.
//
// This pass runs LAST (after virt/subst/bogus/flatten), so sectioning and the rc_k-keyed constants
// do not reduce virt eligibility, and the self-check is emitted over the final code.
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
#include <string>
#include <utility>
#include <vector>

using namespace llvm;

// Must match tools/antitamper_patch.py.
static const uint64_t RC_AT_MAGIC = 0x52435f41545f4d31ull;  // "RC_AT_M1" (little-endian bytes)
static const uint64_t FNV_OFFSET  = 0xcbf29ce484222325ull;
static const uint64_t FNV_PRIME   = 0x100000001b3ull;

PreservedAnalyses AntiTamperPass::run(Module &M, ModuleAnalysisManager &) {
  if (!std::getenv("RUSTCLOAK_ANTITAMPER"))
    return PreservedAnalyses::all();
  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("antitamper:" + M.getName()).str());

  Type *I8 = Type::getInt8Ty(Ctx), *I32 = Type::getInt32Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::get(Ctx, 0);

  // A seeded C-identifier section name (anon() is lead-letter + [a-z0-9], a valid identifier) so the
  // linker emits __start_<sec>/__stop_<sec>. The same name is baked into the descriptor for the tool.
  std::string sec = rustcloak::anon("atsec");
  if (sec.size() > 31) sec.resize(31);

  auto *startSym = new GlobalVariable(M, I8, false, GlobalValue::ExternalLinkage, nullptr,
                                      "__start_" + sec);
  auto *stopSym  = new GlobalVariable(M, I8, false, GlobalValue::ExternalLinkage, nullptr,
                                      "__stop_" + sec);

  // descriptor { i64 magic, i64 expected, i64 namelen, [32 x i8] name } -- data, never in `sec`.
  ArrayType *nameArr = ArrayType::get(I8, 32);
  StructType *descTy = StructType::get(Ctx, {I64, I64, I64, nameArr});
  std::vector<Constant *> nb(32, ConstantInt::get(I8, 0));
  for (size_t i = 0; i < sec.size() && i < 32; i++)
    nb[i] = ConstantInt::get(I8, (uint8_t)sec[i]);
  Constant *descInit = ConstantStruct::get(
      descTy, {ConstantInt::get(I64, RC_AT_MAGIC), ConstantInt::get(I64, 0),
               ConstantInt::get(I64, sec.size()), ConstantArray::get(nameArr, nb)});
  auto *desc = new GlobalVariable(M, descTy, false, GlobalValue::InternalLinkage, descInit,
                                  rustcloak::anon("atd"));
  desc->setAlignment(Align(8));

  auto *rc_k = new GlobalVariable(M, I64, false, GlobalValue::InternalLinkage,
                                  ConstantInt::get(I64, 0), rustcloak::anon("atk"));

  // ---- integrity constructor ----------------------------------------------
  Function *ctor = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                    GlobalValue::InternalLinkage, rustcloak::anon("atc"), M);
  BasicBlock *e = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *cnd = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *bod = BasicBlock::Create(Ctx, "", ctor);
  BasicBlock *don = BasicBlock::Create(Ctx, "", ctor);
  IRBuilder<> B(e);
  AllocaInst *h = B.CreateAlloca(I64);
  AllocaInst *pp = B.CreateAlloca(Ptr);
  B.CreateStore(ConstantInt::get(I64, FNV_OFFSET), h);
  B.CreateStore(startSym, pp);
  B.CreateBr(cnd);
  B.SetInsertPoint(cnd);
  Value *p = B.CreateLoad(Ptr, pp);
  Value *cont = B.CreateICmpULT(B.CreatePtrToInt(p, I64), B.CreatePtrToInt(stopSym, I64));
  B.CreateCondBr(cont, bod, don);
  B.SetInsertPoint(bod);
  LoadInst *byte = B.CreateLoad(I8, p);
  byte->setVolatile(true);
  Value *hv = B.CreateLoad(I64, h);
  hv = B.CreateMul(B.CreateXor(hv, B.CreateZExt(byte, I64)), ConstantInt::get(I64, FNV_PRIME));
  B.CreateStore(hv, h);
  B.CreateStore(B.CreateGEP(I8, p, ConstantInt::get(I64, 1)), pp);
  B.CreateBr(cnd);
  B.SetInsertPoint(don);
  Value *expPtr = B.CreateGEP(descTy, desc, {B.getInt64(0), B.getInt32(1)});
  LoadInst *expv = B.CreateLoad(I64, expPtr);
  expv->setVolatile(true);
  Value *delta = B.CreateXor(B.CreateLoad(I64, h), expv);
  StoreInst *stk = B.CreateStore(delta, rc_k);
  stk->setVolatile(true);
  B.CreateRetVoid();
  appendToGlobalCtors(M, ctor, 0);

  // keep the descriptor whole (its magic/name fields are read only by the tool, not the program).
  appendToUsed(M, {desc});

  // ---- place functions in the protected section + key a few constants ------
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (F.getSection().empty())
      F.setSection(sec);
    if (&F == ctor || F.getEntryBlock().empty())
      continue;

    // one volatile load of rc_k at the entry (dominates the whole function).
    IRBuilder<> BK(&*F.getEntryBlock().getFirstInsertionPt());
    LoadInst *kload = BK.CreateLoad(I64, rc_k);
    kload->setVolatile(true);

    std::vector<std::pair<Instruction *, unsigned>> work;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (&I == kload)
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
      if ((gen() & 3u) == 0u)              // key ~3 in 4: a tamper must corrupt reachable constants
        continue;
      Instruction *I = w.first;
      auto *cst = cast<ConstantInt>(I->getOperand(w.second));
      Type *t = cst->getType();
      IRBuilder<> B2(I);
      Value *kt = t->getIntegerBitWidth() == 64 ? (Value *)kload : B2.CreateTrunc(kload, t);
      I->setOperand(w.second, B2.CreateXor(cst, kt));
    }
  }
  return PreservedAnalyses::none();
}
