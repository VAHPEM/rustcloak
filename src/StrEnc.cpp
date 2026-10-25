//===- StrEnc.cpp - string-literal encryption ------------------------------===//
//
// Every private constant i8 string is XOR-encrypted in the object with a per-string
// keystream (key + index), the global is made writable, and a single shared decrypt
// routine is registered as a global constructor, so the plaintext exists only in
// memory at run time. Statically the file holds only ciphertext -- `strings`/FLOSS
// see nothing; this is the shape rust-deobf's dynamic/emulation engines recover.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <vector>

using namespace llvm;

namespace {

// A shared helper: void xor(i8* p, i64 len, i8 key) { for i: p[i] ^= key + (i8)i; }
Function *getXorHelper(Module &M) {
  LLVMContext &Ctx = M.getContext();
  if (Function *F = M.getFunction(rustcloak::anon("xorh")))
    return F;
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *I8P = PointerType::getUnqual(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), {I8P, I64, I8}, false);
  Function *F = Function::Create(FT, GlobalValue::InternalLinkage, rustcloak::anon("xorh"), M);
  Argument *P = F->getArg(0), *Len = F->getArg(1), *Key = F->getArg(2);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Cond = BasicBlock::Create(Ctx, "cond", F);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", F);

  IRBuilder<> B(Entry);
  AllocaInst *I = B.CreateAlloca(I64, nullptr, "i");
  B.CreateStore(ConstantInt::get(I64, 0), I);
  B.CreateBr(Cond);

  B.SetInsertPoint(Cond);
  Value *iv = B.CreateLoad(I64, I, "iv");
  B.CreateCondBr(B.CreateICmpULT(iv, Len), Body, Exit);

  B.SetInsertPoint(Body);
  Value *ptr = B.CreateGEP(I8, P, iv);
  Value *b = B.CreateLoad(I8, ptr);
  Value *ks = B.CreateAdd(Key, B.CreateTrunc(iv, I8));
  B.CreateStore(B.CreateXor(b, ks), ptr);
  B.CreateStore(B.CreateAdd(iv, ConstantInt::get(I64, 1)), I);
  B.CreateBr(Cond);

  B.SetInsertPoint(Exit);
  B.CreateRetVoid();
  return F;
}

} // namespace

PreservedAnalyses StrEncPass::run(Module &M, ModuleAnalysisManager &) {
  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("strenc:" + M.getName()).str());
  struct Target { GlobalVariable *G; uint8_t key; uint64_t len; };
  std::vector<Target> targets;

  for (GlobalVariable &G : M.globals()) {
    if (!G.hasInitializer() || !G.isConstant())
      continue;
    if (!(G.hasPrivateLinkage() || G.hasInternalLinkage()))
      continue;
    if (G.getName().starts_with("llvm."))
      continue;
    // C strings are a bare `[N x i8]`; Rust wraps them in a one-field struct
    // `<{ [N x i8] }>`. Unwrap the single-element aggregate to find the i8 array.
    Constant *init = G.getInitializer();
    auto *CDA = dyn_cast<ConstantDataArray>(init);
    StructType *wrapTy = nullptr;
    if (!CDA)
      if (auto *CS = dyn_cast<ConstantStruct>(init))
        if (CS->getNumOperands() == 1) {
          CDA = dyn_cast<ConstantDataArray>(CS->getOperand(0));
          wrapTy = CS->getType();
        }
    if (!CDA || !CDA->getElementType()->isIntegerTy(8))
      continue;
    // Referencing a global is always by pointer, so making it writable never breaks
    // another constant; the string is still reached through the same pointer.
    StringRef data = CDA->getRawDataValues();
    if (data.size() < 2 || data.size() > (1u << 16))
      continue;

    uint8_t key = (uint8_t)(gen() | 1u);
    std::vector<uint8_t> enc(data.begin(), data.end());
    for (size_t i = 0; i < enc.size(); i++)
      enc[i] ^= (uint8_t)(key + i);
    Constant *encArr = ConstantDataArray::get(Ctx, enc);
    G.setInitializer(wrapTy ? ConstantStruct::get(wrapTy, {encArr})
                            : encArr);
    G.setConstant(false);
    G.setUnnamedAddr(GlobalValue::UnnamedAddr::None); // the writable copy must not be merged
    targets.push_back({&G, key, enc.size()});
  }
  if (targets.empty())
    return PreservedAnalyses::all();

  Function *Helper = getXorHelper(M);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *Ctor = Function::Create(FT, GlobalValue::InternalLinkage, rustcloak::anon("dctor"), M);
  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Ctor);
  IRBuilder<> B(BB);
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  for (auto &T : targets) {
    Value *P = B.CreateBitCast(T.G, PointerType::getUnqual(Ctx));
    B.CreateCall(Helper, {P, ConstantInt::get(I64, T.len), ConstantInt::get(I8, T.key)});
  }
  B.CreateRetVoid();
  appendToGlobalCtors(M, Ctor, 0);
  return PreservedAnalyses::none();
}
