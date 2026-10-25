//===- Virt.cpp - code virtualization (VM-based obfuscation) ---------------===//
//
// The strongest transform: instead of leaving a function as native machine code,
// `virt` compiles its computation into a custom bytecode for a made-up register
// machine and ships a bytecode *interpreter* in its place. A reverse engineer no
// longer sees x86/ARM arithmetic for that function -- they see a dispatch loop
// over opcodes whose meaning they must first reconstruct, and then a bytecode
// program they must decode. This is the technique behind VMProtect / Themida /
// Tigress; here it is done at the LLVM IR level, so the interpreter LLVM then
// compiles is portable to any target (x86-64 and AArch64 alike).
//
// SCOPE (grows per round; correctness over coverage -- a virtualized function
// must return exactly what the original did):
//   Round 1: single-basic-block integer functions.
//   Round 2 (this): CONTROL FLOW -- multi-block integer functions with branches
//     and loops (and the PHI nodes they create). Opcodes JMP/JZ/JNZ; PHIs are
//     SSA-destructed by splitting critical edges and copying on predecessors.
// Still integer-only (i32/i64 values and the i1 comparisons feed): MEMORY
// (load/store) and CALLS are the next rounds; a function using them is left
// NATIVE.
//
// The virtual ISA is register-based: a fixed array of iW virtual registers, a
// constant pool, and a 4-byte instruction [opcode, dst, a, b]. The bytecode and
// pool are emitted as *mutable* globals read through *volatile* loads, so the
// optimizer cannot constant-fold the interpreter back into the original program
// (devirtualization-by-folding). The interpreter is itself then run through
// subst/bogus/flatten (virt is placed first in the pipeline), compounding it.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <cstdlib>
#include <vector>

using namespace llvm;

namespace {

// Virtual ISA opcodes. 4-byte instruction: [op][dst][a][b].
enum Op : uint8_t {
  OP_RET = 0,     // return reg[a]
  OP_CONST = 1,   // reg[dst] = pool[a | (b<<8)]
  OP_ADD = 2, OP_SUB = 3, OP_MUL = 4, OP_AND = 5, OP_OR = 6, OP_XOR = 7,
  OP_SHL = 8, OP_LSHR = 9, OP_ASHR = 10, OP_UDIV = 11, OP_SDIV = 12,
  OP_UREM = 13, OP_SREM = 14,
  OP_EQ = 16, OP_NE = 17, OP_ULT = 18, OP_ULE = 19, OP_UGT = 20, OP_UGE = 21,
  OP_SLT = 22, OP_SLE = 23, OP_SGT = 24, OP_SGE = 25,
  OP_MOV = 26,    // reg[dst] = reg[a]
  OP_CMOVNZ = 27, // if reg[a] != 0: reg[dst] = reg[b]
  OP_JMP = 28,    // pc = (a | b<<8)
  OP_JZ = 29,     // if reg[dst] == 0: pc = (a | b<<8)  else pc += 4
  OP_JNZ = 30,    // if reg[dst] != 0: pc = (a | b<<8)  else pc += 4
};

// One emitted virtual instruction; branch targets are a BasicBlock* resolved to a
// byte offset once the final layout is known (so no size prediction can go wrong).
struct VI {
  uint8_t op, dst = 0, a = 0, b = 0;
  BasicBlock *tgt = nullptr;   // for JMP/JZ/JNZ: the target block
};

struct Prog {
  std::vector<uint64_t> consts;
  DenseMap<Value *, unsigned> slot;
  DenseMap<uint64_t, unsigned> cpoolIdx, creg;
  std::vector<unsigned> temps;           // shared temp vregs for PHI copies
  unsigned nreg = 0;
};

static uint8_t cmpOp(CmpInst::Predicate p) {
  switch (p) {
  case CmpInst::ICMP_EQ:  return OP_EQ;
  case CmpInst::ICMP_NE:  return OP_NE;
  case CmpInst::ICMP_ULT: return OP_ULT;
  case CmpInst::ICMP_ULE: return OP_ULE;
  case CmpInst::ICMP_UGT: return OP_UGT;
  case CmpInst::ICMP_UGE: return OP_UGE;
  case CmpInst::ICMP_SLT: return OP_SLT;
  case CmpInst::ICMP_SLE: return OP_SLE;
  case CmpInst::ICMP_SGT: return OP_SGT;
  case CmpInst::ICMP_SGE: return OP_SGE;
  default: return 0;
  }
}

static bool isModeledTy(Type *T, unsigned W) {
  return T->isIntegerTy(W) || T->isIntegerTy(1);
}

// Is instruction I one we can compile to bytecode (types match width W)?
static bool okInstr(Instruction &I, unsigned W) {
  if (isa<ReturnInst>(I) || isa<BranchInst>(I) || isa<PHINode>(I))
    return isa<PHINode>(I) ? isModeledTy(I.getType(), W) : true;
  if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
    Type *t = bo->getType();
    if (t->isIntegerTy(W)) {
      switch (bo->getOpcode()) {
      case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
      case Instruction::And: case Instruction::Or:  case Instruction::Xor:
      case Instruction::Shl: case Instruction::LShr: case Instruction::AShr:
      case Instruction::UDiv: case Instruction::SDiv:
      case Instruction::URem: case Instruction::SRem: return true;
      default: return false;
      }
    }
    if (t->isIntegerTy(1)) {
      switch (bo->getOpcode()) {
      case Instruction::And: case Instruction::Or: case Instruction::Xor: return true;
      default: return false;
      }
    }
    return false;
  }
  if (auto *ic = dyn_cast<ICmpInst>(&I))
    return ic->getOperand(0)->getType()->isIntegerTy(W) && cmpOp(ic->getPredicate());
  if (auto *se = dyn_cast<SelectInst>(&I))
    return se->getCondition()->getType()->isIntegerTy(1) && se->getType()->isIntegerTy(W);
  if (auto *ca = dyn_cast<CastInst>(&I)) {
    Type *s = ca->getSrcTy(), *d = ca->getDestTy();
    return (isa<ZExtInst>(ca) && s->isIntegerTy(1) && d->isIntegerTy(W)) ||
           (isa<SExtInst>(ca) && s->isIntegerTy(1) && d->isIntegerTy(W)) ||
           (isa<TruncInst>(ca) && s->isIntegerTy(W) && d->isIntegerTy(1));
  }
  return false;
}

static bool eligible(Function &F, unsigned &W) {
  if (F.isDeclaration() || F.isVarArg())
    return false;
  // return width decides W; every ret must agree
  W = 0;
  for (BasicBlock &BB : F) {
    if (auto *ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
      Value *rv = ret->getReturnValue();
      if (!rv)
        return false;
      unsigned w = rv->getType()->isIntegerTy(32) ? 32 : rv->getType()->isIntegerTy(64) ? 64 : 0;
      if (!w || (W && W != w))
        return false;
      W = w;
    }
  }
  if (!W)
    return false;
  for (Argument &A : F.args())
    if (!A.getType()->isIntegerTy(W))
      return false;
  for (BasicBlock &BB : F) {
    Instruction *term = BB.getTerminator();
    if (!isa<ReturnInst>(term) && !isa<BranchInst>(term))
      return false;                          // no switch/invoke/indirectbr/unreachable
    for (Instruction &I : BB) {
      if (!okInstr(I, W))
        return false;
      for (Value *op : I.operands()) {
        if (isa<BasicBlock>(op))
          continue;                          // branch label
        if (isa<Argument>(op) || isa<Instruction>(op) || isa<ConstantInt>(op))
          continue;
        if (isa<UndefValue>(op))             // undef/poison (e.g. from loop unrolling) -> const 0
          continue;
        return false;
      }
      if (!isModeledTy(I.getType(), W) && !I.getType()->isVoidTy())
        return false;
    }
  }
  return true;
}

} // namespace

PreservedAnalyses VirtPass::run(Function &F, FunctionAnalysisManager &) {
  if (!getenv("RUSTCLOAK_VM"))
    return PreservedAnalyses::all();
  unsigned W = 0;
  if (!eligible(F, W))
    return PreservedAnalyses::all();

  // SSA destruction is simplest once no edge is critical: then every predecessor of a
  // multi-predecessor (PHI-bearing) block has that block as its only successor, so PHI copies
  // can be appended at the end of each predecessor.
  SplitAllCriticalEdges(F);

  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  IntegerType *iW = IntegerType::get(Ctx, W);
  auto maskToW = [&](uint64_t v) -> uint64_t {
    return (W == 64) ? v : (v & ((1ull << W) - 1));
  };

  Prog P;
  for (Argument &A : F.args())
    P.slot[&A] = P.nreg++;
  unsigned maxPhi = 0;
  for (BasicBlock &BB : F) {
    unsigned nph = 0;
    for (Instruction &I : BB) {
      if (isa<PHINode>(I)) nph++;
      if (!isa<ReturnInst>(I) && !isa<BranchInst>(I) && isModeledTy(I.getType(), W))
        P.slot[&I] = P.nreg++;
    }
    maxPhi = std::max(maxPhi, nph);
  }
  auto wantConst = [&](uint64_t v) {
    v = maskToW(v);
    if (P.creg.count(v)) return;
    P.cpoolIdx[v] = (unsigned)P.consts.size();
    P.consts.push_back(v);
    P.creg[v] = P.nreg++;
  };
  bool needZero = false, needTrunc = false;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      for (Value *op : I.operands()) {
        if (auto *ci = dyn_cast<ConstantInt>(op))
          wantConst(ci->getZExtValue());
        if (isa<UndefValue>(op)) needZero = true;   // undef/poison mapped to 0
      }
      if (isa<SExtInst>(&I)) needZero = true;        // sext(i1): 0 - cond
      if (isa<TruncInst>(&I)) needTrunc = true;      // trunc(->i1): x & 1
    }
  if (needZero) wantConst(0);
  if (needTrunc) wantConst(1);
  for (unsigned i = 0; i < maxPhi; i++)
    P.temps.push_back(P.nreg++);
  if (P.nreg > 256 || P.consts.size() > 0xffff)
    return PreservedAnalyses::all();

  auto regOf = [&](Value *v) -> unsigned {
    if (auto *ci = dyn_cast<ConstantInt>(v))
      return P.creg[maskToW(ci->getZExtValue())];
    if (isa<UndefValue>(v))                  // undef: any value is valid; use 0
      return P.creg[0];
    return P.slot[v];
  };

  // ---- emit ----------------------------------------------------------------
  std::vector<VI> code;
  auto emit = [&](uint8_t op, unsigned dst, unsigned a, unsigned b, BasicBlock *tgt = nullptr) {
    code.push_back(VI{op, (uint8_t)dst, (uint8_t)a, (uint8_t)b, tgt});
  };
  // preamble: load every constant once, then fall through into the entry block
  for (auto &kv : P.creg)
    emit(OP_CONST, kv.second, P.cpoolIdx[kv.first] & 0xff, P.cpoolIdx[kv.first] >> 8);

  // PHI copies for the edge pred->S (read all sources to temps, then write -- avoids the
  // lost-copy / swap problem when PHIs reference each other).
  auto phiCopies = [&](BasicBlock *pred, BasicBlock *S) {
    unsigned i = 0;
    std::vector<std::pair<unsigned, unsigned>> moves;   // (phi_slot, src_reg)
    for (PHINode &phi : S->phis()) {
      unsigned src = regOf(phi.getIncomingValueForBlock(pred));
      emit(OP_MOV, P.temps[i], src, 0);                 // temp_i = src
      moves.push_back({P.slot[&phi], P.temps[i]});
      i++;
    }
    for (auto &mv : moves)
      emit(OP_MOV, mv.first, mv.second, 0);             // phi = temp_i
  };

  // emit entry first (so the preamble falls into it), then the rest
  std::vector<BasicBlock *> order;
  order.push_back(&F.getEntryBlock());
  for (BasicBlock &BB : F)
    if (&BB != &F.getEntryBlock())
      order.push_back(&BB);

  DenseMap<BasicBlock *, unsigned> blockStart;
  for (BasicBlock *BB : order) {
    blockStart[BB] = (unsigned)code.size();
    for (Instruction &I : *BB) {
      if (isa<PHINode>(I) || I.isTerminator())
        continue;
      unsigned d = isModeledTy(I.getType(), W) ? regOf(&I) : 0;
      if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
        uint8_t op;
        switch (bo->getOpcode()) {
        case Instruction::Add: op = OP_ADD; break;
        case Instruction::Sub: op = OP_SUB; break;
        case Instruction::Mul: op = OP_MUL; break;
        case Instruction::And: op = OP_AND; break;
        case Instruction::Or:  op = OP_OR;  break;
        case Instruction::Xor: op = OP_XOR; break;
        case Instruction::Shl: op = OP_SHL; break;
        case Instruction::LShr: op = OP_LSHR; break;
        case Instruction::AShr: op = OP_ASHR; break;
        case Instruction::UDiv: op = OP_UDIV; break;
        case Instruction::SDiv: op = OP_SDIV; break;
        case Instruction::URem: op = OP_UREM; break;
        case Instruction::SRem: op = OP_SREM; break;
        default: return PreservedAnalyses::all();
        }
        emit(op, d, regOf(bo->getOperand(0)), regOf(bo->getOperand(1)));
      } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        emit(cmpOp(ic->getPredicate()), d, regOf(ic->getOperand(0)), regOf(ic->getOperand(1)));
      } else if (auto *se = dyn_cast<SelectInst>(&I)) {
        emit(OP_MOV, d, regOf(se->getFalseValue()), 0);
        emit(OP_CMOVNZ, d, regOf(se->getCondition()), regOf(se->getTrueValue()));
      } else if (isa<ZExtInst>(&I)) {
        emit(OP_MOV, d, regOf(I.getOperand(0)), 0);
      } else if (isa<SExtInst>(&I)) {
        emit(OP_SUB, d, P.creg[0], regOf(I.getOperand(0)));
      } else if (isa<TruncInst>(&I)) {
        emit(OP_AND, d, regOf(I.getOperand(0)), P.creg[1]);
      }
    }
    Instruction *term = BB->getTerminator();
    if (auto *ret = dyn_cast<ReturnInst>(term)) {
      emit(OP_RET, 0, regOf(ret->getReturnValue()), 0);
    } else {
      auto *br = cast<BranchInst>(term);
      if (br->isUnconditional()) {
        phiCopies(BB, br->getSuccessor(0));          // safe: pred has a single successor
        emit(OP_JMP, 0, 0, 0, br->getSuccessor(0));
      } else {
        // a conditional-branch block has two successors, so (after edge splitting) neither
        // successor has this block as a non-sole predecessor with a PHI -> no copies here
        emit(OP_JNZ, regOf(br->getCondition()), 0, 0, br->getSuccessor(0));
        emit(OP_JMP, 0, 0, 0, br->getSuccessor(1));
      }
    }
  }

  // resolve branch targets to byte offsets now the layout is fixed
  std::vector<uint8_t> bytes;
  bytes.reserve(code.size() * 4);
  for (VI &vi : code) {
    uint8_t a = vi.a, b = vi.b;
    if (vi.tgt) {
      unsigned off = blockStart[vi.tgt] * 4;
      a = off & 0xff;
      b = (off >> 8) & 0xff;
    }
    bytes.push_back(vi.op);
    bytes.push_back(vi.dst);
    bytes.push_back(a);
    bytes.push_back(b);
  }

  // ---- globals -------------------------------------------------------------
  Constant *bcInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(bytes));
  auto *bc = new GlobalVariable(M, bcInit->getType(), /*isConstant=*/false,
                                GlobalValue::InternalLinkage, bcInit, rustcloak::anon("vb"));
  Constant *poolInit;
  if (W == 32) {
    std::vector<uint32_t> v(P.consts.begin(), P.consts.end());
    poolInit = ConstantDataArray::get(Ctx, ArrayRef<uint32_t>(v));
  } else {
    poolInit = ConstantDataArray::get(Ctx, ArrayRef<uint64_t>(P.consts));
  }
  auto *pool = new GlobalVariable(M, poolInit->getType(), /*isConstant=*/false,
                                  GlobalValue::InternalLinkage, poolInit, rustcloak::anon("vp"));

  // ---- rebuild F as the interpreter ----------------------------------------
  SmallVector<Argument *, 8> args;
  for (Argument &A : F.args())
    args.push_back(&A);
  std::vector<BasicBlock *> olds;
  for (BasicBlock &O : F)
    olds.push_back(&O);
  for (BasicBlock *O : olds)
    O->dropAllReferences();
  for (BasicBlock *O : olds)
    O->eraseFromParent();

  BasicBlock *entry = BasicBlock::Create(Ctx, "", &F);
  BasicBlock *loop = BasicBlock::Create(Ctx, "", &F);
  BasicBlock *bad = BasicBlock::Create(Ctx, "", &F);
  Type *i8 = Type::getInt8Ty(Ctx), *i64 = Type::getInt64Ty(Ctx);
  ArrayType *regsTy = ArrayType::get(iW, P.nreg);

  IRBuilder<> B(entry);
  Value *regs = B.CreateAlloca(regsTy);
  auto regGEP = [&](Value *idx) { return B.CreateGEP(regsTy, regs, {B.getInt64(0), idx}); };
  for (unsigned i = 0; i < args.size(); i++)
    B.CreateStore(args[i], regGEP(B.getInt64(P.slot[args[i]])));
  B.CreateBr(loop);

  B.SetInsertPoint(loop);
  PHINode *pc = B.CreatePHI(i64, 1 + 32);
  pc->addIncoming(B.getInt64(0), entry);
  ArrayType *bcTy = cast<ArrayType>(bcInit->getType());
  auto bcByte = [&](Value *off) {
    LoadInst *l = B.CreateLoad(i8, B.CreateGEP(bcTy, bc, {B.getInt64(0), off}));
    l->setVolatile(true);
    return l;
  };
  Value *op = bcByte(pc);
  Value *dst = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(1))), i64);
  Value *ra = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(2))), i64);
  Value *rb = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(3))), i64);
  Value *pc4 = B.CreateAdd(pc, B.getInt64(4));
  Value *tgt = B.CreateOr(ra, B.CreateShl(rb, 8));

  auto loadReg = [&](Value *idx) { return B.CreateLoad(iW, regGEP(idx)); };
  auto storeReg = [&](Value *idx, Value *v) { B.CreateStore(v, regGEP(idx)); };

  bool seen[256] = {false};
  for (size_t i = 0; i < bytes.size(); i += 4)
    seen[bytes[i]] = true;
  std::vector<uint8_t> present;
  for (int i = 0; i < 256; i++)
    if (seen[i]) present.push_back((uint8_t)i);

  SwitchInst *sw = B.CreateSwitch(op, bad, present.size());
  ArrayType *poolTy = cast<ArrayType>(poolInit->getType());

  auto finish = [&](Value *nextpc) {           // close a handler: feed pc, loop
    pc->addIncoming(nextpc, B.GetInsertBlock());
    B.CreateBr(loop);
  };

  for (uint8_t oc : present) {
    BasicBlock *h = BasicBlock::Create(Ctx, "", &F, bad);
    sw->addCase(ConstantInt::get(cast<IntegerType>(i8), oc), h);
    B.SetInsertPoint(h);
    if (oc == OP_RET) { B.CreateRet(loadReg(ra)); continue; }
    if (oc == OP_JMP) { finish(tgt); continue; }
    if (oc == OP_JZ)  { finish(B.CreateSelect(B.CreateICmpEQ(loadReg(dst), ConstantInt::get(iW, 0)), tgt, pc4)); continue; }
    if (oc == OP_JNZ) { finish(B.CreateSelect(B.CreateICmpNE(loadReg(dst), ConstantInt::get(iW, 0)), tgt, pc4)); continue; }
    if (oc == OP_CONST) {
      LoadInst *l = B.CreateLoad(iW, B.CreateGEP(poolTy, pool, {B.getInt64(0), tgt}));
      l->setVolatile(true);
      storeReg(dst, l);
      finish(pc4);
      continue;
    }
    Value *va = loadReg(ra), *vb = loadReg(rb), *r = nullptr;
    switch (oc) {
    case OP_ADD: r = B.CreateAdd(va, vb); break;
    case OP_SUB: r = B.CreateSub(va, vb); break;
    case OP_MUL: r = B.CreateMul(va, vb); break;
    case OP_AND: r = B.CreateAnd(va, vb); break;
    case OP_OR:  r = B.CreateOr(va, vb);  break;
    case OP_XOR: r = B.CreateXor(va, vb); break;
    case OP_SHL: r = B.CreateShl(va, vb); break;
    case OP_LSHR: r = B.CreateLShr(va, vb); break;
    case OP_ASHR: r = B.CreateAShr(va, vb); break;
    case OP_UDIV: r = B.CreateUDiv(va, vb); break;
    case OP_SDIV: r = B.CreateSDiv(va, vb); break;
    case OP_UREM: r = B.CreateURem(va, vb); break;
    case OP_SREM: r = B.CreateSRem(va, vb); break;
    case OP_MOV:  r = va; break;
    case OP_CMOVNZ:
      r = B.CreateSelect(B.CreateICmpNE(va, ConstantInt::get(iW, 0)), vb, loadReg(dst));
      break;
    default: {
      CmpInst::Predicate p = CmpInst::ICMP_EQ;
      switch (oc) {
      case OP_EQ: p = CmpInst::ICMP_EQ; break;  case OP_NE: p = CmpInst::ICMP_NE; break;
      case OP_ULT: p = CmpInst::ICMP_ULT; break; case OP_ULE: p = CmpInst::ICMP_ULE; break;
      case OP_UGT: p = CmpInst::ICMP_UGT; break; case OP_UGE: p = CmpInst::ICMP_UGE; break;
      case OP_SLT: p = CmpInst::ICMP_SLT; break; case OP_SLE: p = CmpInst::ICMP_SLE; break;
      case OP_SGT: p = CmpInst::ICMP_SGT; break; case OP_SGE: p = CmpInst::ICMP_SGE; break;
      }
      r = B.CreateZExt(B.CreateICmp(p, va, vb), iW);
      break;
    }
    }
    storeReg(dst, r);
    finish(pc4);
  }

  B.SetInsertPoint(bad);
  B.CreateUnreachable();
  return PreservedAnalyses::none();
}
