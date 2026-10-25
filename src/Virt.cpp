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
// ROUND 1 SCOPE (honest, correct subset -- expanded in later rounds):
//   * single-basic-block functions returning i32 or i64 (no branches/loops/phi yet),
//   * integer parameters of that same width,
//   * instructions limited to: integer add/sub/mul/and/or/xor/shl/lshr/ashr/
//     udiv/sdiv/urem/srem, icmp, select, and the i1<->iW zext/sext/trunc that
//     comparisons feed; boolean and/or/xor on i1 is allowed too.
// Anything else (memory, calls, multiple blocks, other widths, floats, vectors)
// leaves the function NATIVE. Correctness over coverage: a virtualized function
// must return exactly what the original did. Later rounds add control flow
// (branch opcodes), memory (load/store opcodes) and calls.
//
// The virtual ISA is register-based: a fixed array of iW virtual registers, a
// constant pool, and a 4-byte instruction [opcode, dst, a, b]. The bytecode and
// pool are emitted as *mutable* globals read through *volatile* loads, so the
// optimizer cannot constant-fold the interpreter back into the original program
// (devirtualization-by-folding). The interpreter is itself then run through
// subst/bogus/flatten (virt is placed first in the pipeline), compounding the
// protection.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

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
};

struct Prog {
  std::vector<uint8_t> code;      // 4 bytes per instruction
  std::vector<uint64_t> consts;   // constant pool (each masked to W bits)
  unsigned nreg = 0;
  DenseMap<Value *, unsigned> slot;      // arg/instruction result -> vreg
  DenseMap<uint64_t, unsigned> cpoolIdx; // constant value -> pool index
  DenseMap<uint64_t, unsigned> creg;     // constant value -> vreg holding it

  void emit(uint8_t op, unsigned dst, unsigned a, unsigned b) {
    code.push_back(op);
    code.push_back((uint8_t)dst);
    code.push_back((uint8_t)a);
    code.push_back((uint8_t)b);
  }
};

// Map an ICmp predicate to a virtual opcode (0 => not representable).
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

// Is this a value we model in a vreg: an integer of the VM width W, or an i1?
static bool isModeledTy(Type *T, unsigned W) {
  return T->isIntegerTy(W) || T->isIntegerTy(1);
}

// Decide whether F is eligible for round-1 virtualization; set W (32 or 64).
static bool eligible(Function &F, unsigned &W) {
  if (F.isDeclaration() || F.isVarArg())
    return false;
  if (F.size() != 1)                              // single basic block only (no CFG yet)
    return false;
  auto *ret = dyn_cast<ReturnInst>(F.back().getTerminator());
  if (!ret || !ret->getReturnValue())
    return false;
  Type *rt = ret->getReturnValue()->getType();
  if (rt->isIntegerTy(32)) W = 32;
  else if (rt->isIntegerTy(64)) W = 64;
  else return false;

  for (Argument &A : F.args())
    if (!A.getType()->isIntegerTy(W))             // params must be exactly iW
      return false;

  for (Instruction &I : F.front()) {
    if (isa<ReturnInst>(I))
      continue;
    // operands: only args, earlier modeled instructions, or ConstantInt
    for (Value *op : I.operands()) {
      if (isa<Argument>(op) || isa<Instruction>(op))
        continue;
      if (isa<ConstantInt>(op))
        continue;
      return false;                               // globals, exprs, undef, etc. -> native
    }
    if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
      Type *t = bo->getType();
      if (t->isIntegerTy(W)) {
        switch (bo->getOpcode()) {
        case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
        case Instruction::And: case Instruction::Or:  case Instruction::Xor:
        case Instruction::Shl: case Instruction::LShr: case Instruction::AShr:
        case Instruction::UDiv: case Instruction::SDiv:
        case Instruction::URem: case Instruction::SRem:
          break;
        default: return false;
        }
      } else if (t->isIntegerTy(1)) {
        // boolean and/or/xor on i1 (0/1-valued regs): bitwise == boolean here
        switch (bo->getOpcode()) {
        case Instruction::And: case Instruction::Or: case Instruction::Xor: break;
        default: return false;
        }
      } else {
        return false;
      }
    } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
      if (!ic->getOperand(0)->getType()->isIntegerTy(W) || !cmpOp(ic->getPredicate()))
        return false;
    } else if (auto *se = dyn_cast<SelectInst>(&I)) {
      if (!se->getCondition()->getType()->isIntegerTy(1) ||
          !se->getType()->isIntegerTy(W))
        return false;
    } else if (auto *ca = dyn_cast<CastInst>(&I)) {
      Type *s = ca->getSrcTy(), *d = ca->getDestTy();
      bool ok = (isa<ZExtInst>(ca) && s->isIntegerTy(1) && d->isIntegerTy(W)) ||
                (isa<SExtInst>(ca) && s->isIntegerTy(1) && d->isIntegerTy(W)) ||
                (isa<TruncInst>(ca) && s->isIntegerTy(W) && d->isIntegerTy(1));
      if (!ok)
        return false;
    } else {
      return false;                               // call/load/store/phi/gep/... -> native
    }
    if (!isModeledTy(I.getType(), W) && !I.getType()->isVoidTy())
      return false;
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

  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  IntegerType *iW = IntegerType::get(Ctx, W);
  BasicBlock &BB = F.front();
  auto *ret = cast<ReturnInst>(BB.getTerminator());

  Prog P;
  unsigned mask64bits = W;                         // for masking constants
  auto maskToW = [&](uint64_t v) -> uint64_t {
    return (W == 64) ? v : (v & ((1ull << mask64bits) - 1));
  };

  // ---- pass A: assign vregs -------------------------------------------------
  for (Argument &A : F.args())
    P.slot[&A] = P.nreg++;
  for (Instruction &I : BB)
    if (!isa<ReturnInst>(I) && isModeledTy(I.getType(), W))
      P.slot[&I] = P.nreg++;

  // constants (including those feeding the ret), each a pool entry + a vreg
  auto wantConst = [&](uint64_t v) {
    v = maskToW(v);
    if (P.creg.count(v))
      return;
    P.cpoolIdx[v] = (unsigned)P.consts.size();
    P.consts.push_back(v);
    P.creg[v] = P.nreg++;
  };
  bool needSext = false, needTrunc = false;
  for (Instruction &I : BB) {
    for (Value *op : I.operands())
      if (auto *ci = dyn_cast<ConstantInt>(op))
        wantConst(ci->getZExtValue());
    if (isa<SExtInst>(&I)) needSext = true;
    if (isa<TruncInst>(&I)) needTrunc = true;
  }
  if (needSext) wantConst(0);                      // sext(i1): 0 - cond
  if (needTrunc) wantConst(1);                     // trunc(->i1): x & 1

  if (P.nreg > 256 || P.consts.size() > 0xffff)    // vreg index is a byte; pool index u16
    return PreservedAnalyses::all();

  auto regOf = [&](Value *v) -> unsigned {
    if (auto *ci = dyn_cast<ConstantInt>(v))
      return P.creg[maskToW(ci->getZExtValue())];
    return P.slot[v];
  };

  // ---- pass B: emit bytecode ------------------------------------------------
  for (auto &kv : P.creg)                          // load every constant first
    P.emit(OP_CONST, kv.second, P.cpoolIdx[kv.first] & 0xff, P.cpoolIdx[kv.first] >> 8);
  for (Instruction &I : BB) {
    if (isa<ReturnInst>(I))
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
      P.emit(op, d, regOf(bo->getOperand(0)), regOf(bo->getOperand(1)));
    } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
      P.emit(cmpOp(ic->getPredicate()), d, regOf(ic->getOperand(0)), regOf(ic->getOperand(1)));
    } else if (auto *se = dyn_cast<SelectInst>(&I)) {
      P.emit(OP_MOV, d, regOf(se->getFalseValue()), 0);
      P.emit(OP_CMOVNZ, d, regOf(se->getCondition()), regOf(se->getTrueValue()));
    } else if (isa<ZExtInst>(&I)) {
      P.emit(OP_MOV, d, regOf(I.getOperand(0)), 0);
    } else if (isa<SExtInst>(&I)) {
      P.emit(OP_SUB, d, P.creg[0], regOf(I.getOperand(0)));
    } else if (isa<TruncInst>(&I)) {
      P.emit(OP_AND, d, regOf(I.getOperand(0)), P.creg[1]);
    }
  }
  P.emit(OP_RET, 0, regOf(ret->getReturnValue()), 0);

  // ---- build the globals ----------------------------------------------------
  Constant *bcInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(P.code));
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
  SmallVector<Value *, 8> args;
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
  BasicBlock *advance = BasicBlock::Create(Ctx, "", &F);
  BasicBlock *bad = BasicBlock::Create(Ctx, "", &F);

  Type *i8 = Type::getInt8Ty(Ctx);
  Type *i64 = Type::getInt64Ty(Ctx);
  ArrayType *regsTy = ArrayType::get(iW, P.nreg);

  IRBuilder<> B(entry);
  Value *regs = B.CreateAlloca(regsTy);
  auto regGEP = [&](Value *idx) {
    return B.CreateGEP(regsTy, regs, {B.getInt64(0), idx});
  };
  // load the arguments into their vregs
  for (unsigned i = 0; i < args.size(); i++)
    B.CreateStore(args[i], regGEP(B.getInt64(P.slot[cast<Argument>(args[i])])));
  B.CreateBr(loop);

  // loop header: decode the 4 bytes at pc, then switch on the opcode
  B.SetInsertPoint(loop);
  PHINode *pc = B.CreatePHI(i64, 2);
  pc->addIncoming(B.getInt64(0), entry);
  ArrayType *bcTy = cast<ArrayType>(bcInit->getType());
  auto bcByte = [&](Value *off) {
    Value *g = B.CreateGEP(bcTy, bc, {B.getInt64(0), off});
    LoadInst *l = B.CreateLoad(i8, g);
    l->setVolatile(true);                          // block constant-folding the interpreter away
    return l;
  };
  Value *op = bcByte(pc);
  Value *dst = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(1))), i64);
  Value *ra = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(2))), i64);
  Value *rb = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(3))), i64);

  auto loadReg = [&](Value *idx) {
    return B.CreateLoad(iW, regGEP(idx));
  };
  auto storeReg = [&](Value *idx, Value *val) {
    B.CreateStore(val, regGEP(idx));
  };

  // collect which opcodes actually occur, so we only emit their handlers
  std::vector<uint8_t> present;
  {
    bool seen[256] = {false};
    for (size_t i = 0; i < P.code.size(); i += 4)
      seen[P.code[i]] = true;
    for (int i = 0; i < 256; i++)
      if (seen[i])
        present.push_back((uint8_t)i);
  }

  SwitchInst *sw = B.CreateSwitch(op, bad, present.size());
  ArrayType *poolTy = cast<ArrayType>(poolInit->getType());

  for (uint8_t oc : present) {
    BasicBlock *h = BasicBlock::Create(Ctx, "", &F, advance);
    sw->addCase(ConstantInt::get(cast<IntegerType>(i8), oc), h);
    B.SetInsertPoint(h);
    if (oc == OP_RET) {
      B.CreateRet(loadReg(ra));
      continue;
    }
    if (oc == OP_CONST) {
      Value *idx = B.CreateOr(ra, B.CreateShl(rb, 8));
      Value *g = B.CreateGEP(poolTy, pool, {B.getInt64(0), idx});
      LoadInst *l = B.CreateLoad(iW, g);
      l->setVolatile(true);
      storeReg(dst, l);
      B.CreateBr(advance);
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
    case OP_CMOVNZ: {
      Value *nz = B.CreateICmpNE(va, ConstantInt::get(iW, 0));
      r = B.CreateSelect(nz, vb, loadReg(dst));
      break;
    }
    default: {
      // a comparison: dst = (va <pred> vb) ? 1 : 0
      CmpInst::Predicate p;
      switch (oc) {
      case OP_EQ: p = CmpInst::ICMP_EQ; break;
      case OP_NE: p = CmpInst::ICMP_NE; break;
      case OP_ULT: p = CmpInst::ICMP_ULT; break;
      case OP_ULE: p = CmpInst::ICMP_ULE; break;
      case OP_UGT: p = CmpInst::ICMP_UGT; break;
      case OP_UGE: p = CmpInst::ICMP_UGE; break;
      case OP_SLT: p = CmpInst::ICMP_SLT; break;
      case OP_SLE: p = CmpInst::ICMP_SLE; break;
      case OP_SGT: p = CmpInst::ICMP_SGT; break;
      case OP_SGE: p = CmpInst::ICMP_SGE; break;
      default: p = CmpInst::ICMP_EQ; break;
      }
      r = B.CreateZExt(B.CreateICmp(p, va, vb), iW);
      break;
    }
    }
    storeReg(dst, r);
    B.CreateBr(advance);
  }

  B.SetInsertPoint(advance);
  Value *next = B.CreateAdd(pc, B.getInt64(4));
  pc->addIncoming(next, advance);
  B.CreateBr(loop);

  B.SetInsertPoint(bad);
  B.CreateUnreachable();

  return PreservedAnalyses::none();
}
