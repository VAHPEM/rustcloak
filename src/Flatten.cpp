//===- Flatten.cpp - control-flow flattening -------------------------------===//
//
// Rewrites each function into the canonical flattened form: a switch-variable, a
// dispatcher, and original blocks that transition by assigning the next state
// constant. The original order of the blocks is hidden in a runtime state machine.
// Classic flattening (Wang et al.); original implementation.
//
// Flattening breaks SSA dominance (a block is now reached through the dispatcher,
// not by direct domination), so PHIs and every value used outside its defining
// block are demoted to stack first. Functions with exception handling / indirectbr
// / switch terminators are left untouched.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h"

#include <vector>

using namespace llvm;

namespace {

// Only functions whose every terminator this pass can rewrite are eligible.
bool eligible(Function &F) {
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
    // A dynamic (variable-size) alloca outside the entry block cannot be hoisted to entry
    // without changing semantics, and left in place it will not dominate its uses once the
    // CFG runs through the dispatcher. Such functions are left untouched.
    if (&BB != &F.getEntryBlock())
      for (Instruction &I : BB)
        if (auto *AI = dyn_cast<AllocaInst>(&I))
          if (!AI->isStaticAlloca())
            return false;
  }
  return true;
}

// Hoist every static alloca into the entry block. Once control flow is routed through the
// dispatcher, the entry block dominates every case, but an alloca left in a non-entry block
// does not dominate its uses (rustc/LLVM do place allocas outside entry, and llvm.lifetime.end
// then references one across blocks) -- which breaks SSA. Hoisting fixes that generally.
void hoistAllocas(Function &F) {
  BasicBlock &E = F.getEntryBlock();
  Instruction *ip = &*E.getFirstInsertionPt();
  std::vector<AllocaInst *> movers;
  for (BasicBlock &BB : F) {
    if (&BB == &E)
      continue;
    for (Instruction &I : BB)
      if (auto *AI = dyn_cast<AllocaInst>(&I))
        movers.push_back(AI);
  }
  for (AllocaInst *AI : movers)
    AI->moveBefore(ip);
}

// Demote PHIs and any value used outside its block to stack (reg2mem).
void lowerToMemory(Function &F) {
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

bool flatten(Function &F, std::mt19937_64 &rng) {
  if (!eligible(F))
    return false;
  hoistAllocas(F);
  LLVMContext &Ctx = F.getContext();
  IntegerType *I32 = Type::getInt32Ty(Ctx);

  // Split a conditional entry terminator so the entry falls through to one block.
  BasicBlock *Entry = &F.getEntryBlock();
  if (auto *Br = dyn_cast<BranchInst>(Entry->getTerminator()))
    if (Br->isConditional())
      Entry->splitBasicBlock(Br, "");

  auto *EntryBr = dyn_cast<BranchInst>(Entry->getTerminator());
  if (!EntryBr || EntryBr->isConditional())
    return false;
  BasicBlock *First = EntryBr->getSuccessor(0);

  lowerToMemory(F);
  EntryBr = cast<BranchInst>(Entry->getTerminator());

  std::vector<BasicBlock *> Blocks;
  for (BasicBlock &BB : F)
    if (&BB != Entry)
      Blocks.push_back(&BB);
  if (Blocks.size() <= 1)
    return false;

  // A distinct random state constant per block.
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

  IRBuilder<> B(EntryBr);
  AllocaInst *SwVar = B.CreateAlloca(I32, nullptr, "");
  B.CreateStore(B.getInt32(State[First]), SwVar);

  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "", &F);
  BasicBlock *DispatchEnd = BasicBlock::Create(Ctx, "", &F);

  EntryBr->eraseFromParent();
  BranchInst::Create(Dispatch, Entry);

  IRBuilder<> BD(Dispatch);
  LoadInst *Cur = BD.CreateLoad(I32, SwVar, "");
  BD.CreateBr(DispatchEnd);

  SwitchInst *SW = SwitchInst::Create(Cur, Dispatch, Blocks.size(), DispatchEnd);
  for (BasicBlock *BB : Blocks)
    SW->addCase(ConstantInt::get(I32, State[BB]), BB);

  for (BasicBlock *BB : Blocks) {
    Instruction *T = BB->getTerminator();
    if (isa<ReturnInst>(T) || isa<UnreachableInst>(T))
      continue;
    auto *Br = dyn_cast<BranchInst>(T);
    if (!Br)
      continue;
    IRBuilder<> BB_(T);
    if (Br->isUnconditional()) {
      BB_.CreateStore(BB_.getInt32(State[Br->getSuccessor(0)]), SwVar);
    } else {
      Value *Sel = BB_.CreateSelect(Br->getCondition(),
                                    BB_.getInt32(State[Br->getSuccessor(0)]),
                                    BB_.getInt32(State[Br->getSuccessor(1)]), "");
      BB_.CreateStore(Sel, SwVar);
    }
    BB_.CreateBr(Dispatch);
    T->eraseFromParent();
  }
  return true;
}

} // namespace

PreservedAnalyses FlattenPass::run(Function &F, FunctionAnalysisManager &) {
  auto gen = rustcloak::rng(("flatten:" + F.getName()).str());
  return flatten(F, gen) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
