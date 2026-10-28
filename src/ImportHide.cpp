//===- ImportHide.cpp - hide selected imports behind dlsym-by-name ----------===//
//
// RUSTCLOAK_HIDE_IMPORTS="name1,name2,...". Each named external function that is called directly in
// the module is resolved once at startup via dlsym(RTLD_DEFAULT, <name>), where <name> is stored
// XOR-encrypted and decrypted into a stack buffer (through volatile loads, so the optimizer cannot
// fold the plaintext back in) just before the dlsym; every direct call is then rewritten to an
// indirect call through the resolved pointer. The function no longer appears as a direct import or
// in `strings` -- only dlsym and an encrypted byte string remain -- yet behaviour is identical,
// since dlsym returns the same function. Needs libdl (glibc >= 2.34 has it in libc).
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
#include <vector>

using namespace llvm;

PreservedAnalyses ImportHidePass::run(Module &M, ModuleAnalysisManager &) {
  const char *env = std::getenv("RUSTCLOAK_HIDE_IMPORTS");
  if (!env)
    return PreservedAnalyses::all();

  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("imphide:" + M.getName()).str());
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::get(Ctx, 0);

  // parse the comma-separated name list
  std::vector<std::string> names;
  std::string list = env;
  for (size_t p = 0; p <= list.size();) {
    size_t c = list.find(',', p);
    std::string tok = list.substr(p, c == std::string::npos ? std::string::npos : c - p);
    if (!tok.empty())
      names.push_back(tok);
    if (c == std::string::npos)
      break;
    p = c + 1;
  }

  FunctionCallee dlsymFn = M.getOrInsertFunction("dlsym", FunctionType::get(Ptr, {Ptr, Ptr}, false));

  struct Cand { Function *F; GlobalVariable *enc, *keyG, *hp; unsigned len; };
  std::vector<Cand> cands;
  for (const std::string &nm : names) {
    Function *F = M.getFunction(nm);
    if (!F || !F->isDeclaration() || F->isIntrinsic())
      continue;
    bool anyCall = false;
    for (User *U : F->users())
      if (auto *ci = dyn_cast<CallInst>(U))
        if (ci->getCalledFunction() == F) { anyCall = true; break; }
    if (!anyCall)
      continue;
    uint8_t key = (uint8_t)(gen() | 1u);
    std::vector<uint8_t> e(nm.begin(), nm.end());
    for (uint8_t &b : e)
      b ^= key;
    Constant *encInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(e));
    auto *encG = new GlobalVariable(M, encInit->getType(), false, GlobalValue::InternalLinkage,
                                    encInit, rustcloak::anon("ie"));
    auto *keyG = new GlobalVariable(M, I8, false, GlobalValue::InternalLinkage,
                                    ConstantInt::get(I8, key), rustcloak::anon("ik"));
    auto *hp = new GlobalVariable(M, Ptr, false, GlobalValue::InternalLinkage,
                                  ConstantPointerNull::get(cast<PointerType>(Ptr)),
                                  rustcloak::anon("ih"));
    cands.push_back({F, encG, keyG, hp, (unsigned)nm.size()});
  }
  if (cands.empty())
    return PreservedAnalyses::all();

  // resolver ctor: for each candidate, decrypt the name into a stack buffer and dlsym it.
  Function *ctor = Function::Create(FunctionType::get(Type::getVoidTy(Ctx), false),
                                    GlobalValue::InternalLinkage, rustcloak::anon("ic"), M);
  BasicBlock *entry = BasicBlock::Create(Ctx, "", ctor);
  IRBuilder<> B(entry);
  std::vector<AllocaInst *> bufs, idxs;
  for (auto &cd : cands) {
    bufs.push_back(B.CreateAlloca(ArrayType::get(I8, cd.len + 1)));
    idxs.push_back(B.CreateAlloca(I64));
  }
  for (size_t ci = 0; ci < cands.size(); ci++) {
    Cand &cd = cands[ci];
    ArrayType *bufTy = ArrayType::get(I8, cd.len + 1);
    ArrayType *encTy = cast<ArrayType>(cd.enc->getValueType());
    BasicBlock *cnd = BasicBlock::Create(Ctx, "", ctor);
    BasicBlock *bod = BasicBlock::Create(Ctx, "", ctor);
    BasicBlock *aft = BasicBlock::Create(Ctx, "", ctor);
    B.CreateStore(ConstantInt::get(I64, 0), idxs[ci]);
    B.CreateBr(cnd);
    B.SetInsertPoint(cnd);
    Value *iv = B.CreateLoad(I64, idxs[ci]);
    B.CreateCondBr(B.CreateICmpULT(iv, ConstantInt::get(I64, cd.len)), bod, aft);
    B.SetInsertPoint(bod);
    LoadInst *eb = B.CreateLoad(I8, B.CreateGEP(encTy, cd.enc, {B.getInt64(0), iv}));
    eb->setVolatile(true);
    LoadInst *kb = B.CreateLoad(I8, cd.keyG);
    kb->setVolatile(true);
    B.CreateStore(B.CreateXor(eb, kb), B.CreateGEP(bufTy, bufs[ci], {B.getInt64(0), iv}));
    B.CreateStore(B.CreateAdd(iv, B.getInt64(1)), idxs[ci]);
    B.CreateBr(cnd);
    B.SetInsertPoint(aft);
    B.CreateStore(ConstantInt::get(I8, 0),
                  B.CreateGEP(bufTy, bufs[ci], {B.getInt64(0), B.getInt64(cd.len)}));
    Value *bufP = B.CreateGEP(bufTy, bufs[ci], {B.getInt64(0), B.getInt64(0)});
    Value *fp = B.CreateCall(dlsymFn, {ConstantPointerNull::get(cast<PointerType>(Ptr)), bufP});
    B.CreateStore(fp, cd.hp);
  }
  B.CreateRetVoid();
  appendToGlobalCtors(M, ctor, 0);

  // rewrite each direct call to a candidate into an indirect call through the resolved pointer.
  for (auto &cd : cands) {
    std::vector<CallInst *> sites;
    for (User *U : cd.F->users())
      if (auto *c = dyn_cast<CallInst>(U))
        if (c->getCalledFunction() == cd.F)
          sites.push_back(c);
    for (CallInst *c : sites) {
      IRBuilder<> B2(c);
      LoadInst *fp = B2.CreateLoad(Ptr, cd.hp);
      c->setCalledOperand(fp);             // same FunctionType is retained on the call
    }
  }
  return PreservedAnalyses::none();
}
