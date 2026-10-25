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
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdlib>
#include <vector>

using namespace llvm;

namespace {

struct EncTarget { GlobalVariable *G; uint8_t key; uint64_t len; };

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

// Eager mode: one global constructor that decrypts all the given strings before main().
void emitStartupCtor(Module &M, Function *Helper, ArrayRef<EncTarget> targets) {
  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *Ctor = Function::Create(FT, GlobalValue::InternalLinkage, rustcloak::anon("dctor"), M);
  IRBuilder<> B(BasicBlock::Create(Ctx, "entry", Ctor));
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  for (auto &T : targets) {
    Value *P = B.CreateBitCast(T.G, PointerType::getUnqual(Ctx));
    B.CreateCall(Helper, {P, ConstantInt::get(I64, T.len), ConstantInt::get(I8, T.key)});
  }
  B.CreateRetVoid();
  appendToGlobalCtors(M, Ctor, 0);
}

// Lazy mode (RUSTCLOAK_LAZY): give one encrypted global its own getter that decrypts it on first
// use -- guarded by a flag -- and returns its pointer, then redirect every use of the global to a
// call of that getter. The plaintext then exists in memory only once the string is actually used,
// and only for the strings that are reached, so a dump at startup (or of an unused path) sees only
// ciphertext. Returns false and changes nothing if the global has a use that is not a plain
// instruction operand (e.g. a ConstantExpr or a global initializer), so the caller can fall back to
// decrypting it eagerly. (The flag check is not synchronised; a program that first touches the same
// string from several threads at once would need a once-guard -- noted for a future revision.)
// Rewrite every ConstantExpr that uses G (e.g. a `getelementptr` into the array) into an
// equivalent instruction at each site that uses it, so that afterwards all of G's uses are plain
// instruction operands the getter can be threaded through.
void expandConstantUsers(GlobalVariable *G) {
  bool changed = true;
  while (changed) {
    changed = false;
    for (User *U : llvm::make_early_inc_range(G->users())) {
      auto *CE = dyn_cast<ConstantExpr>(U);
      if (!CE)
        continue;
      for (Use &CU : llvm::make_early_inc_range(CE->uses())) {
        auto *I = dyn_cast<Instruction>(CU.getUser());
        if (!I)
          continue;                      // nested constexpr: handled on a later sweep
        Instruction *ip = I;
        if (auto *PN = dyn_cast<PHINode>(I))
          ip = PN->getIncomingBlock(CU)->getTerminator();
        Instruction *ni = CE->getAsInstruction(ip);
        CU.set(ni);
        changed = true;
      }
    }
  }
}

bool makeLazy(Module &M, Function *Helper, const EncTarget &T) {
  LLVMContext &Ctx = M.getContext();
  Type *I1 = Type::getInt1Ty(Ctx), *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *Ptr = PointerType::getUnqual(Ctx);
  GlobalVariable *G = T.G;

  expandConstantUsers(G);
  std::vector<Use *> uses;               // snapshot before we add the getter's own uses of G
  for (Use &U : G->uses()) {
    if (!isa<Instruction>(U.getUser()))
      return false;                      // not safely redirectable -> defer to the eager ctor
    uses.push_back(&U);
  }
  if (uses.empty())
    return true;                         // encrypted but never referenced: nothing to redirect

  auto *Flag = new GlobalVariable(M, I1, /*isConstant=*/false, GlobalValue::InternalLinkage,
                                  ConstantInt::getFalse(Ctx), rustcloak::anon("f"));
  Function *Get = Function::Create(FunctionType::get(Ptr, false),
                                   GlobalValue::InternalLinkage, rustcloak::anon("g"), M);
  BasicBlock *entry = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *dec = BasicBlock::Create(Ctx, "", Get);
  BasicBlock *done = BasicBlock::Create(Ctx, "", Get);
  IRBuilder<> B(entry);
  B.CreateCondBr(B.CreateLoad(I1, Flag), done, dec);
  B.SetInsertPoint(dec);
  B.CreateCall(Helper, {G, ConstantInt::get(I64, T.len), ConstantInt::get(I8, T.key)});
  B.CreateStore(ConstantInt::getTrue(Ctx), Flag);
  B.CreateBr(done);
  B.SetInsertPoint(done);
  B.CreateRet(G);

  for (Use *U : uses) {
    auto *I = cast<Instruction>(U->getUser());
    Instruction *ip = I;
    if (auto *PN = dyn_cast<PHINode>(I))  // a phi operand must be ready in its incoming block
      ip = PN->getIncomingBlock(*U)->getTerminator();
    CallInst *c = CallInst::Create(Get->getFunctionType(), Get, {}, "", ip);
    U->set(c);
  }
  return true;
}

} // namespace

PreservedAnalyses StrEncPass::run(Module &M, ModuleAnalysisManager &) {
  LLVMContext &Ctx = M.getContext();
  auto gen = rustcloak::rng(("strenc:" + M.getName()).str());
  std::vector<EncTarget> targets;

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
  // RUSTCLOAK_LAZY turns on on-demand decryption: each string decrypts the first time it is used,
  // not at startup. Default (unset) keeps the eager startup-constructor behaviour, so the build is
  // never affected unless the mode is explicitly requested.
  if (std::getenv("RUSTCLOAK_LAZY")) {
    std::vector<EncTarget> deferred;
    for (auto &T : targets)
      if (!makeLazy(M, Helper, T))
        deferred.push_back(T);           // not lazifiable -> still encrypted, decrypted eagerly
    if (!deferred.empty())
      emitStartupCtor(M, Helper, deferred);
  } else {
    emitStartupCtor(M, Helper, targets);
  }
  return PreservedAnalyses::none();
}
