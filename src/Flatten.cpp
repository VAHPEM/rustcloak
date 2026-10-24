//===- Flatten.cpp - control-flow flattening pass (RustCloak) --------------===//
//
// A from-scratch implementation of OLLVM-style control-flow flattening for the
// LLVM new pass manager. Each function is rewritten into the canonical flattened
// form -- a switch-variable, a dispatcher loop, and original blocks that transition
// by assigning the next state constant -- so the original order of the blocks is
// hidden in a runtime state machine. This is the classic flattening algorithm
// (Wang et al.); the code here is original, not copied from Obfuscator-LLVM.
//
// Correctness: flattening breaks SSA dominance (a block is now reached through the
// dispatcher, not by direct domination), so every value that is used outside its
// defining block is first demoted to a stack slot (reg2mem), and PHI nodes are
// demoted too. Functions with exception handling, indirectbr, or switch terminators
// are left untouched in this version.
//
//   opt -load-pass-plugin=./libRustCloak.so -passes=flatten in.ll -o out.ll
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <cstdlib>
#include <random>
#include <vector>

using namespace llvm;

static cl::opt<bool> FlattenAll("flatten-all", cl::init(true),
                                cl::desc("flatten every eligible function"));

namespace {

// A function is eligible only if every terminator is one this version can rewrite.
static bool eligible(Function &F) {
  if (F.isDeclaration() || F.size() <= 1)
    return false;
  for (BasicBlock &BB : F) {
    Instruction *T = BB.getTerminator();
    if (isa<InvokeInst>(T) || isa<IndirectBrInst>(T) || isa<SwitchInst>(T) ||
        isa<CallBrInst>(T) || isa<CatchSwitchInst>(T) || isa<CatchReturnInst>(T) ||
        isa<CleanupReturnInst>(T) || isa<ResumeInst>(T))
      return false;
    if (BB.isLandingPad() || BB.isEHPad())
      return false;
  }
  return true;
}

// Demote PHIs and any value used outside its block to stack, so rewiring control
// flow cannot violate dominance.
static void lowerToMemory(Function &F) {
  std::vector<PHINode *> phis;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *P = dyn_cast<PHINode>(&I))
        phis.push_back(P);
  for (PHINode *P : phis)
    DemotePHIToStack(P);

  std::vector<Instruction *> cross;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      if (isa<AllocaInst>(&I) || I.isTerminator())
        continue;
      for (User *U : I.users())
        if (auto *UI = dyn_cast<Instruction>(U))
          if (UI->getParent() != I.getParent()) {
            cross.push_back(&I);
            break;
          }
    }
  for (Instruction *I : cross)
    DemoteRegToStack(*I);
}

static bool flatten(Function &F, std::mt19937 &rng) {
  if (!eligible(F))
    return false;

  LLVMContext &Ctx = F.getContext();
  IntegerType *I32 = Type::getInt32Ty(Ctx);

  // If the entry block ends in a conditional branch, split it so the condition
  // computation stays in the entry and the branch becomes an ordinary block.
  BasicBlock *Entry = &F.getEntryBlock();
  if (auto *Br = dyn_cast<BranchInst>(Entry->getTerminator()))
    if (Br->isConditional())
      Entry->splitBasicBlock(Br, "entry.split");

  // The first real block is whatever the (now unconditional) entry branches to.
  auto *EntryBr = dyn_cast<BranchInst>(Entry->getTerminator());
  if (!EntryBr || EntryBr->isConditional())
    return false; // entry does not fall through to a single successor
  BasicBlock *First = EntryBr->getSuccessor(0);

  lowerToMemory(F);

  // Re-read entry terminator (lowerToMemory may add stores but not change the branch).
  EntryBr = cast<BranchInst>(Entry->getTerminator());

  // Collect the blocks to flatten (everything except the entry).
  std::vector<BasicBlock *> Blocks;
  for (BasicBlock &BB : F)
    if (&BB != Entry)
      Blocks.push_back(&BB);
  if (Blocks.size() <= 1)
    return false;

  // Assign a distinct random state constant to each block.
  DenseMap<BasicBlock *, uint32_t> State;
  DenseMap<uint32_t, bool> used;
  std::uniform_int_distribution<uint32_t> dist(1, 0xffffffffu);
  for (BasicBlock *BB : Blocks) {
    uint32_t v;
    do {
      v = dist(rng);
    } while (used.count(v));
    used[v] = true;
    State[BB] = v;
  }

  // switchVar in the entry block.
  IRBuilder<> B(EntryBr);
  AllocaInst *SwVar = B.CreateAlloca(I32, nullptr, "cloak.state");
  B.CreateStore(B.getInt32(State[First]), SwVar);

  // Dispatcher: load the state, switch to the matching block.
  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "cloak.dispatch", &F);
  BasicBlock *DispatchEnd = BasicBlock::Create(Ctx, "cloak.dispatch.end", &F);

  // entry -> dispatch
  EntryBr->eraseFromParent();
  BranchInst::Create(Dispatch, Entry);

  // dispatch: %s = load state; br dispatch.end
  IRBuilder<> BD(Dispatch);
  LoadInst *Cur = BD.CreateLoad(I32, SwVar, "cloak.cur");
  BD.CreateBr(DispatchEnd);

  // dispatch.end: switch %s, default -> dispatch (unreachable in practice)
  SwitchInst *SW = SwitchInst::Create(Cur, Dispatch, Blocks.size(), DispatchEnd);
  for (BasicBlock *BB : Blocks)
    SW->addCase(ConstantInt::get(I32, State[BB]), BB);

  // Rewrite each block's terminator to set the next state and jump to the dispatcher.
  for (BasicBlock *BB : Blocks) {
    Instruction *T = BB->getTerminator();
    if (isa<ReturnInst>(T) || isa<UnreachableInst>(T))
      continue; // genuine exits stay
    auto *Br = dyn_cast<BranchInst>(T);
    if (!Br)
      continue;
    IRBuilder<> BB_(T);
    if (Br->isUnconditional()) {
      BB_.CreateStore(BB_.getInt32(State[Br->getSuccessor(0)]), SwVar);
    } else {
      Value *Sel =
          BB_.CreateSelect(Br->getCondition(),
                           BB_.getInt32(State[Br->getSuccessor(0)]),
                           BB_.getInt32(State[Br->getSuccessor(1)]), "cloak.next");
      BB_.CreateStore(Sel, SwVar);
    }
    BB_.CreateBr(Dispatch);
    T->eraseFromParent();
  }
  return true;
}

struct FlattenPass : PassInfoMixin<FlattenPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    std::mt19937 rng(std::hash<std::string>{}(F.getName().str()) ^ 0x9e3779b9u);
    bool changed = flatten(F, rng);
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

//===----------------------------------------------------------------------===//
// String-literal encryption
//
// Each private constant i8 string global is XOR-encrypted in the object with a
// per-string keystream (key + index), the global is made writable, and a single
// shared decrypt routine is registered as a global constructor so the strings are
// restored in memory before main runs. Statically the file holds only ciphertext;
// the plaintext exists only at runtime -- the shape rust-deobf's dynamic/emulation
// engines are built to recover, and `strings` / FLOSS are not.
//===----------------------------------------------------------------------===//

// A shared helper: void xor(i8* p, i64 len, i8 key) { for i: p[i] ^= key + (i8)i; }
static Function *getXorHelper(Module &M) {
  LLVMContext &Ctx = M.getContext();
  if (Function *F = M.getFunction("rustcloak.xor"))
    return F;
  Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
  Type *I8P = PointerType::getUnqual(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), {I8P, I64, I8}, false);
  Function *F = Function::Create(FT, GlobalValue::InternalLinkage, "rustcloak.xor", M);
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

struct StrEncPass : PassInfoMixin<StrEncPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &Ctx = M.getContext();
    std::mt19937 rng(0x5c10a4u ^ std::hash<std::string>{}(M.getName().str()));
    struct Target { GlobalVariable *G; uint8_t key; uint64_t len; };
    std::vector<Target> targets;

    for (GlobalVariable &G : M.globals()) {
      if (!G.hasInitializer() || !G.isConstant())
        continue;
      if (!(G.hasPrivateLinkage() || G.hasInternalLinkage()))
        continue;
      auto *CDA = dyn_cast<ConstantDataArray>(G.getInitializer());
      if (!CDA || !CDA->getElementType()->isIntegerTy(8))
        continue;
      // Skip strings referenced from other constants (making them writable is unsafe there).
      bool unsafe = false;
      for (User *U : G.users())
        if (isa<Constant>(U) && !isa<GlobalValue>(U)) { unsafe = true; break; }
      if (unsafe)
        continue;
      StringRef data = CDA->getRawDataValues();
      if (data.size() < 2 || data.size() > (1u << 16))
        continue;

      uint8_t key = (uint8_t)(rng() | 1u);
      std::vector<uint8_t> enc(data.begin(), data.end());
      for (size_t i = 0; i < enc.size(); i++)
        enc[i] ^= (uint8_t)(key + i);
      G.setInitializer(ConstantDataArray::get(Ctx, enc));
      G.setConstant(false);
      targets.push_back({&G, key, enc.size()});
    }
    if (targets.empty())
      return PreservedAnalyses::all();

    // A constructor that decrypts every target in place before main.
    Function *Helper = getXorHelper(M);
    FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
    Function *Ctor =
        Function::Create(FT, GlobalValue::InternalLinkage, "rustcloak.decrypt", M);
    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> B(BB);
    Type *I8 = Type::getInt8Ty(Ctx), *I64 = Type::getInt64Ty(Ctx);
    for (auto &T : targets) {
      Value *P = B.CreateBitCast(T.G, PointerType::getUnqual(Ctx));
      B.CreateCall(Helper, {P, ConstantInt::get(I64, T.len),
                            ConstantInt::get(I8, T.key)});
    }
    B.CreateRetVoid();
    appendToGlobalCtors(M, Ctor, 0);
    return PreservedAnalyses::none();
  }
  static bool isRequired() { return true; }
};

} // namespace

llvm::PassPluginLibraryInfo getRustCloakPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "RustCloak", "0.1",
          [](PassBuilder &PB) {
            // explicit: `-passes=flatten` (function) and `-passes=strenc` (module)
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "flatten") {
                    FPM.addPass(FlattenPass());
                    return true;
                  }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "strenc") {
                    MPM.addPass(StrEncPass());
                    return true;
                  }
                  return false;
                });
            // Loading the plugin into a default -O pipeline (clang/opt -O2 -fpass-plugin=...)
            // obfuscates at the END of the pipeline, so the optimizer's own passes cannot undo
            // the flattening. Set RUSTCLOAK_OFF to disable this automatic insertion.
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  if (getenv("RUSTCLOAK_OFF"))
                    return;
                  MPM.addPass(StrEncPass());
                  MPM.addPass(createModuleToFunctionPassAdaptor(FlattenPass()));
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getRustCloakPluginInfo();
}
