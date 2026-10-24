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

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"

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

} // namespace

llvm::PassPluginLibraryInfo getRustCloakPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "RustCloak", "0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "flatten") {
                    FPM.addPass(FlattenPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getRustCloakPluginInfo();
}
