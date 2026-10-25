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
// must behave exactly like the original):
//   Round 1: single-basic-block integer functions.
//   Round 2: control flow -- multi-block, branches and loops (PHI nodes).
//   Round 3 (this): MEMORY -- loads, stores and getelementptr, pointers, and
//     mixed integer widths (i8/i16/i32/i64). So a real buffer routine (a decode
//     loop over arrays) virtualizes whole. The virtual machine is now a uniform
//     i64 register file; each width-sensitive opcode carries its width in its two
//     high bits, and loads/stores hit real process memory (the interpreter runs
//     natively -- no memory emulation). Calls, globals, floats and vectors are
//     still left native.
//
// The bytecode and constant pool are *mutable* globals read through *volatile*
// loads, so the optimizer cannot constant-fold the interpreter back into the
// original program. virt runs first in the pipeline, so subst/bogus/flatten then
// obfuscate the interpreter itself.
//
//===----------------------------------------------------------------------===//
#include "RustCloak.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <numeric>
#include <vector>

using namespace llvm;

namespace {

// Base opcodes (6 bits). The two high bits of the opcode byte carry a width code for the
// width-sensitive ops (arithmetic, compare, load, store, sext): 0=i8, 1=i16, 2=i32, 3=i64.
enum Op : uint8_t {
  OP_RET = 0,     // return reg[a] (truncated to the function's return type)
  OP_CONST = 1,   // reg[dst] = pool[a | (b<<8)]
  OP_ADD = 2, OP_SUB = 3, OP_MUL = 4, OP_AND = 5, OP_OR = 6, OP_XOR = 7,
  OP_SHL = 8, OP_LSHR = 9, OP_ASHR = 10, OP_UDIV = 11, OP_SDIV = 12,
  OP_UREM = 13, OP_SREM = 14,
  OP_EQ = 16, OP_NE = 17, OP_ULT = 18, OP_ULE = 19, OP_UGT = 20, OP_UGE = 21,
  OP_SLT = 22, OP_SLE = 23, OP_SGT = 24, OP_SGE = 25,
  OP_MOV = 26,    // reg[dst] = reg[a]        (full 64-bit copy: ptr<->int, zext, bitcast)
  OP_CMOVNZ = 27, // if reg[a] != 0: reg[dst] = reg[b]
  OP_JMP = 28,    // pc = (a | b<<8)
  OP_JZ = 29,     // if reg[dst] == 0: pc = target  else pc += 4
  OP_JNZ = 30,    // if reg[dst] != 0: pc = target  else pc += 4
  OP_LOAD = 32,   // reg[dst] = zext( *(iW*)reg[a] )
  OP_STORE = 33,  // *(iW*)reg[a] = trunc(reg[b], iW)   (dst unused)
  OP_SEXT = 34,   // reg[dst] = sext( trunc(reg[a], iW) )  -- sign-extend from W bits to 64
  OP_RETV = 35,   // return void
};

static uint8_t wcodeOf(unsigned bits) {
  return bits == 8 ? 0 : bits == 16 ? 1 : bits == 32 ? 2 : 3;
}

struct VI {
  uint8_t op, dst = 0, a = 0, b = 0;
  BasicBlock *tgt = nullptr;
};

struct Prog {
  std::vector<uint64_t> consts;
  DenseMap<Value *, unsigned> slot;
  DenseMap<uint64_t, unsigned> cpoolIdx, creg;
  std::vector<unsigned> temps;          // PHI copy temporaries
  unsigned gepTmp = 0;                   // one scratch reg for GEP address arithmetic
  unsigned nreg = 0;
};

static uint8_t cmpBase(CmpInst::Predicate p) {
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

// A value the VM can hold in an i64 register: a small-enough integer, or a pointer.
static bool isRegTy(Type *T) {
  return (T->isIntegerTy() && T->getIntegerBitWidth() <= 64) || T->isPointerTy();
}

static bool okOperand(Value *v) {
  return isa<Argument>(v) || isa<Instruction>(v) || isa<ConstantInt>(v) ||
         isa<UndefValue>(v) || isa<ConstantPointerNull>(v);
}

static bool eligible(Function &F) {
  if (F.isDeclaration() || F.isVarArg())
    return false;
  for (Argument &A : F.args())
    if (!isRegTy(A.getType()))
      return false;
  for (BasicBlock &BB : F) {
    Instruction *term = BB.getTerminator();
    if (auto *ret = dyn_cast<ReturnInst>(term)) {
      Value *rv = ret->getReturnValue();
      if (rv && !(rv->getType()->isIntegerTy() && rv->getType()->getIntegerBitWidth() <= 64))
        return false;                    // int or void return only (no pointer returns yet)
    } else if (!isa<BranchInst>(term)) {
      return false;
    }
    for (Instruction &I : BB) {
      if (!I.getType()->isVoidTy() && !isRegTy(I.getType()))
        return false;
      bool ok = false;
      if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
        ok = bo->getType()->isIntegerTy() && bo->getType()->getIntegerBitWidth() <= 64;
      } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        ok = ic->getOperand(0)->getType()->isIntegerTy() && cmpBase(ic->getPredicate());
      } else if (auto *se = dyn_cast<SelectInst>(&I)) {
        ok = se->getCondition()->getType()->isIntegerTy(1) && isRegTy(se->getType());
      } else if (isa<TruncInst>(&I) || isa<ZExtInst>(&I) || isa<SExtInst>(&I)) {
        ok = I.getType()->isIntegerTy() && I.getOperand(0)->getType()->isIntegerTy();
      } else if (isa<PtrToIntInst>(&I) || isa<IntToPtrInst>(&I)) {
        ok = true;
      } else if (auto *bc = dyn_cast<BitCastInst>(&I)) {
        ok = bc->getType()->isPointerTy() && bc->getSrcTy()->isPointerTy();
      } else if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        ok = true;
        for (auto it = gep_type_begin(gep), e = gep_type_end(gep); it != e; ++it)
          if (it.getStructTypeOrNull() && !isa<ConstantInt>(it.getOperand()))
            ok = false;                  // struct index must be constant (always true in valid IR)
      } else if (auto *ld = dyn_cast<LoadInst>(&I)) {
        ok = !ld->isAtomic() && !ld->isVolatile() &&
             ld->getType()->isIntegerTy() && ld->getType()->getIntegerBitWidth() <= 64;
      } else if (auto *st = dyn_cast<StoreInst>(&I)) {
        Type *vt = st->getValueOperand()->getType();
        ok = !st->isAtomic() && !st->isVolatile() &&
             vt->isIntegerTy() && vt->getIntegerBitWidth() <= 64;
      } else if (isa<PHINode>(&I)) {
        ok = isRegTy(I.getType());
      } else if (isa<ReturnInst>(&I) || isa<BranchInst>(&I)) {
        ok = true;
      }
      if (!ok)
        return false;
      for (Value *op : I.operands()) {
        if (isa<BasicBlock>(op))
          continue;
        if (!okOperand(op))
          return false;                  // globals / constexprs / float consts -> native
      }
    }
  }
  return true;
}

} // namespace

PreservedAnalyses VirtPass::run(Function &F, FunctionAnalysisManager &) {
  if (!getenv("RUSTCLOAK_VM"))
    return PreservedAnalyses::all();
  if (!eligible(F))
    return PreservedAnalyses::all();

  // Per-build, per-function opcode encoding: the logical opcode -> byte mapping is a seeded random
  // permutation of the low 6 bits, so two builds (or two functions) share no VM instruction set and
  // a deobfuscator cannot assume fixed opcode numbers -- it must recover the map from the handlers.
  // The width still rides in the top two bits.
  std::array<uint8_t, 64> enc;           // enc[logical base] = emitted byte-base
  std::iota(enc.begin(), enc.end(), 0);
  std::shuffle(enc.begin(), enc.end(), rustcloak::rng(("vmenc:" + F.getName()).str()));

  SplitAllCriticalEdges(F);              // so PHI copies can live at predecessors

  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  const DataLayout &DL = M.getDataLayout();
  Type *i64 = Type::getInt64Ty(Ctx);

  auto widthOf = [](Value *v) -> unsigned {
    Type *t = v->getType();
    return t->isIntegerTy() ? t->getIntegerBitWidth() : 64;   // pointers: 64-bit lane
  };

  Prog P;
  for (Argument &A : F.args())
    P.slot[&A] = P.nreg++;
  unsigned maxPhi = 0;
  for (BasicBlock &BB : F) {
    unsigned nph = 0;
    for (Instruction &I : BB) {
      if (isa<PHINode>(I))
        nph++;
      if (!I.isTerminator() && !I.getType()->isVoidTy() && isRegTy(I.getType()))
        P.slot[&I] = P.nreg++;
    }
    maxPhi = std::max(maxPhi, nph);
  }

  auto wantConst = [&](uint64_t v) {
    if (P.creg.count(v)) return;
    P.cpoolIdx[v] = (unsigned)P.consts.size();
    P.consts.push_back(v);
    P.creg[v] = P.nreg++;
  };
  // constants, GEP strides/offsets, and the masks sext/trunc need
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      for (Value *op : I.operands())
        if (auto *ci = dyn_cast<ConstantInt>(op))
          wantConst(ci->getZExtValue());
      if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        for (auto it = gep_type_begin(gep), e = gep_type_end(gep); it != e; ++it) {
          if (it.getStructTypeOrNull())
            continue;
          wantConst(DL.getTypeAllocSize(it.getIndexedType()).getFixedValue());
        }
      }
    }
  wantConst(0);
  for (unsigned i = 0; i < maxPhi; i++)
    P.temps.push_back(P.nreg++);
  P.gepTmp = P.nreg++;
  if (P.nreg > 256 || P.consts.size() > 0xffff)
    return PreservedAnalyses::all();

  auto regOf = [&](Value *v) -> unsigned {
    if (auto *ci = dyn_cast<ConstantInt>(v))
      return P.creg[ci->getZExtValue()];
    if (isa<UndefValue>(v) || isa<ConstantPointerNull>(v))
      return P.creg[0];
    return P.slot[v];
  };

  std::vector<VI> code;
  auto emit = [&](uint8_t base, unsigned width, unsigned dst, unsigned a, unsigned b,
                  BasicBlock *tgt = nullptr) {
    code.push_back(VI{(uint8_t)(enc[base] | (wcodeOf(width) << 6)), (uint8_t)dst,
                      (uint8_t)a, (uint8_t)b, tgt});
  };
  for (auto &kv : P.creg)
    emit(OP_CONST, 64, kv.second, P.cpoolIdx[kv.first] & 0xff, P.cpoolIdx[kv.first] >> 8);

  auto phiCopies = [&](BasicBlock *pred, BasicBlock *S) {
    unsigned i = 0;
    std::vector<std::pair<unsigned, unsigned>> mv;
    for (PHINode &phi : S->phis()) {
      emit(OP_MOV, 64, P.temps[i], regOf(phi.getIncomingValueForBlock(pred)), 0);
      mv.push_back({P.slot[&phi], P.temps[i]});
      i++;
    }
    for (auto &m : mv)
      emit(OP_MOV, 64, m.first, m.second, 0);
  };

  // lower a getelementptr to i64 address arithmetic, result in reg `dst`
  auto lowerGEP = [&](GetElementPtrInst *gep, unsigned dst) {
    emit(OP_MOV, 64, dst, regOf(gep->getPointerOperand()), 0);   // dst = base
    uint64_t constOff = 0;
    for (auto it = gep_type_begin(gep), e = gep_type_end(gep); it != e; ++it) {
      Value *idx = it.getOperand();
      if (StructType *STy = it.getStructTypeOrNull()) {
        unsigned f = cast<ConstantInt>(idx)->getZExtValue();
        constOff += DL.getStructLayout(STy)->getElementOffset(f);
        continue;
      }
      uint64_t stride = DL.getTypeAllocSize(it.getIndexedType()).getFixedValue();
      if (auto *ci = dyn_cast<ConstantInt>(idx)) {
        constOff += (uint64_t)ci->getSExtValue() * stride;
        continue;
      }
      // variable index: sign-extend to 64, multiply by the stride, add on
      unsigned ir = regOf(idx);
      if (widthOf(idx) < 64) {
        emit(OP_SEXT, widthOf(idx), P.gepTmp, ir, 0);
        ir = P.gepTmp;
      }
      emit(OP_MUL, 64, P.gepTmp, ir, P.creg[stride]);
      emit(OP_ADD, 64, dst, dst, P.gepTmp);
    }
    if (constOff)
      emit(OP_ADD, 64, dst, dst, P.creg[constOff & 0xffffffffffffffffull]);
  };

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
      unsigned d = (!I.getType()->isVoidTy() && isRegTy(I.getType())) ? regOf(&I) : 0;
      if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
        static const DenseMap<unsigned, uint8_t> M = {
          {Instruction::Add, OP_ADD}, {Instruction::Sub, OP_SUB}, {Instruction::Mul, OP_MUL},
          {Instruction::And, OP_AND}, {Instruction::Or, OP_OR}, {Instruction::Xor, OP_XOR},
          {Instruction::Shl, OP_SHL}, {Instruction::LShr, OP_LSHR}, {Instruction::AShr, OP_ASHR},
          {Instruction::UDiv, OP_UDIV}, {Instruction::SDiv, OP_SDIV},
          {Instruction::URem, OP_UREM}, {Instruction::SRem, OP_SREM}};
        auto f = M.find(bo->getOpcode());
        if (f == M.end())
          return PreservedAnalyses::all();
        emit(f->second, widthOf(bo), d, regOf(bo->getOperand(0)), regOf(bo->getOperand(1)));
      } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        emit(cmpBase(ic->getPredicate()), widthOf(ic->getOperand(0)), d,
             regOf(ic->getOperand(0)), regOf(ic->getOperand(1)));
      } else if (auto *se = dyn_cast<SelectInst>(&I)) {
        emit(OP_MOV, 64, d, regOf(se->getFalseValue()), 0);
        emit(OP_CMOVNZ, 64, d, regOf(se->getCondition()), regOf(se->getTrueValue()));
      } else if (isa<ZExtInst>(&I)) {
        // values are kept zero-extended in their 64-bit lane, so a zext is just a copy
        emit(OP_MOV, 64, d, regOf(I.getOperand(0)), 0);
      } else if (isa<SExtInst>(&I)) {
        emit(OP_SEXT, widthOf(I.getOperand(0)), d, regOf(I.getOperand(0)), 0);
      } else if (auto *tr = dyn_cast<TruncInst>(&I)) {
        unsigned w = widthOf(tr);
        wantConst(w >= 64 ? ~0ull : ((1ull << w) - 1));
        emit(OP_AND, 64, d, regOf(tr->getOperand(0)), P.creg[w >= 64 ? ~0ull : ((1ull << w) - 1)]);
      } else if (isa<PtrToIntInst>(&I) || isa<IntToPtrInst>(&I) || isa<BitCastInst>(&I)) {
        emit(OP_MOV, 64, d, regOf(I.getOperand(0)), 0);
      } else if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        lowerGEP(gep, d);
      } else if (auto *ld = dyn_cast<LoadInst>(&I)) {
        emit(OP_LOAD, ld->getType()->getIntegerBitWidth(), d, regOf(ld->getPointerOperand()), 0);
      } else if (auto *st = dyn_cast<StoreInst>(&I)) {
        emit(OP_STORE, st->getValueOperand()->getType()->getIntegerBitWidth(), 0,
             regOf(st->getPointerOperand()), regOf(st->getValueOperand()));
      }
    }
    Instruction *term = BB->getTerminator();
    if (auto *ret = dyn_cast<ReturnInst>(term)) {
      if (ret->getReturnValue())
        emit(OP_RET, 64, 0, regOf(ret->getReturnValue()), 0);
      else
        emit(OP_RETV, 64, 0, 0, 0);
    } else {
      auto *br = cast<BranchInst>(term);
      if (br->isUnconditional()) {
        phiCopies(BB, br->getSuccessor(0));
        emit(OP_JMP, 64, 0, 0, 0, br->getSuccessor(0));
      } else {
        emit(OP_JNZ, 64, regOf(br->getCondition()), 0, 0, br->getSuccessor(0));
        emit(OP_JMP, 64, 0, 0, 0, br->getSuccessor(1));
      }
    }
  }

  std::vector<uint8_t> bytes;
  bytes.reserve(code.size() * 4);
  for (VI &vi : code) {
    uint8_t a = vi.a, b = vi.b;
    if (vi.tgt) {
      unsigned off = blockStart[vi.tgt] * 4;
      a = off & 0xff;
      b = (off >> 8) & 0xff;
    }
    bytes.insert(bytes.end(), {vi.op, vi.dst, a, b});
  }

  // ---- globals -------------------------------------------------------------
  Constant *bcInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(bytes));
  auto *bc = new GlobalVariable(M, bcInit->getType(), false, GlobalValue::InternalLinkage,
                                bcInit, rustcloak::anon("vb"));
  Constant *poolInit = ConstantDataArray::get(Ctx, ArrayRef<uint64_t>(P.consts));
  auto *pool = new GlobalVariable(M, poolInit->getType(), false, GlobalValue::InternalLinkage,
                                  poolInit, rustcloak::anon("vp"));

  // ---- rebuild F as the interpreter ----------------------------------------
  SmallVector<Argument *, 8> args;
  for (Argument &A : F.args())
    args.push_back(&A);
  Type *retTy = F.getReturnType();
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
  Type *i8 = Type::getInt8Ty(Ctx);
  ArrayType *regsTy = ArrayType::get(i64, P.nreg);

  IRBuilder<> B(entry);
  Value *regs = B.CreateAlloca(regsTy);
  auto regGEP = [&](Value *idx) { return B.CreateGEP(regsTy, regs, {B.getInt64(0), idx}); };
  for (unsigned i = 0; i < args.size(); i++) {
    Value *v = args[i];
    if (v->getType()->isPointerTy())
      v = B.CreatePtrToInt(v, i64);
    else
      v = B.CreateZExt(v, i64);
    B.CreateStore(v, regGEP(B.getInt64(P.slot[args[i]])));
  }
  B.CreateBr(loop);

  B.SetInsertPoint(loop);
  PHINode *pc = B.CreatePHI(i64, 1 + 64);
  pc->addIncoming(B.getInt64(0), entry);
  ArrayType *bcTy = cast<ArrayType>(bcInit->getType());
  auto bcByte = [&](Value *o) {
    LoadInst *l = B.CreateLoad(i8, B.CreateGEP(bcTy, bc, {B.getInt64(0), o}));
    l->setVolatile(true);
    return l;
  };
  Value *opByte = bcByte(pc);
  Value *dst = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(1))), i64);
  Value *ra = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(2))), i64);
  Value *rb = B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(3))), i64);
  Value *pc4 = B.CreateAdd(pc, B.getInt64(4));
  Value *tgt = B.CreateOr(ra, B.CreateShl(rb, 8));
  auto loadReg = [&](Value *idx) { return B.CreateLoad(i64, regGEP(idx)); };
  auto storeReg = [&](Value *idx, Value *v) { B.CreateStore(v, regGEP(idx)); };

  bool seen[256] = {false};
  for (size_t i = 0; i < bytes.size(); i += 4)
    seen[bytes[i]] = true;
  std::vector<unsigned> present;
  for (int i = 0; i < 256; i++)
    if (seen[i])
      present.push_back(i);

  SwitchInst *sw = B.CreateSwitch(opByte, bad, present.size());
  ArrayType *poolTy = cast<ArrayType>(poolInit->getType());
  auto finish = [&](Value *nextpc) {
    pc->addIncoming(nextpc, B.GetInsertBlock());
    B.CreateBr(loop);
  };

  std::array<uint8_t, 64> dec;           // invert the opcode encoding for handler generation
  for (unsigned i = 0; i < 64; i++)
    dec[enc[i]] = (uint8_t)i;
  static const unsigned WBITS[4] = {8, 16, 32, 64};
  for (unsigned ob : present) {
    uint8_t base = dec[ob & 0x3f];
    unsigned wbits = WBITS[(ob >> 6) & 3];
    Type *iW = IntegerType::get(Ctx, wbits);
    BasicBlock *h = BasicBlock::Create(Ctx, "", &F, bad);
    sw->addCase(ConstantInt::get(cast<IntegerType>(i8), ob), h);
    B.SetInsertPoint(h);

    if (base == OP_RETV) { B.CreateRetVoid(); continue; }
    if (base == OP_RET) {
      Value *v = loadReg(ra);
      if (retTy->isIntegerTy() && retTy->getIntegerBitWidth() < 64)
        v = B.CreateTrunc(v, retTy);
      B.CreateRet(v);
      continue;
    }
    if (base == OP_JMP) { finish(tgt); continue; }
    if (base == OP_JZ)  { finish(B.CreateSelect(B.CreateICmpEQ(loadReg(dst), B.getInt64(0)), tgt, pc4)); continue; }
    if (base == OP_JNZ) { finish(B.CreateSelect(B.CreateICmpNE(loadReg(dst), B.getInt64(0)), tgt, pc4)); continue; }
    if (base == OP_CONST) {
      LoadInst *l = B.CreateLoad(i64, B.CreateGEP(poolTy, pool, {B.getInt64(0), tgt}));
      l->setVolatile(true);
      storeReg(dst, l);
      finish(pc4);
      continue;
    }
    if (base == OP_MOV) { storeReg(dst, loadReg(ra)); finish(pc4); continue; }
    if (base == OP_CMOVNZ) {
      storeReg(dst, B.CreateSelect(B.CreateICmpNE(loadReg(ra), B.getInt64(0)), loadReg(rb), loadReg(dst)));
      finish(pc4);
      continue;
    }
    if (base == OP_SEXT) {
      storeReg(dst, B.CreateSExt(B.CreateTrunc(loadReg(ra), iW), i64));
      finish(pc4);
      continue;
    }
    if (base == OP_LOAD) {
      Value *p = B.CreateIntToPtr(loadReg(ra), PointerType::get(Ctx, 0));
      Value *v = B.CreateZExt(B.CreateLoad(iW, p), i64);
      storeReg(dst, v);
      finish(pc4);
      continue;
    }
    if (base == OP_STORE) {
      Value *p = B.CreateIntToPtr(loadReg(ra), PointerType::get(Ctx, 0));
      B.CreateStore(B.CreateTrunc(loadReg(rb), iW), p);
      finish(pc4);
      continue;
    }
    // width-sensitive arithmetic / comparison: operate at width W, keep the lane zero-extended
    Value *va = B.CreateTrunc(loadReg(ra), iW), *vb = B.CreateTrunc(loadReg(rb), iW), *r = nullptr;
    switch (base) {
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
    default: {
      CmpInst::Predicate p = CmpInst::ICMP_EQ;
      switch (base) {
      case OP_EQ: p = CmpInst::ICMP_EQ; break;  case OP_NE: p = CmpInst::ICMP_NE; break;
      case OP_ULT: p = CmpInst::ICMP_ULT; break; case OP_ULE: p = CmpInst::ICMP_ULE; break;
      case OP_UGT: p = CmpInst::ICMP_UGT; break; case OP_UGE: p = CmpInst::ICMP_UGE; break;
      case OP_SLT: p = CmpInst::ICMP_SLT; break; case OP_SLE: p = CmpInst::ICMP_SLE; break;
      case OP_SGT: p = CmpInst::ICMP_SGT; break; case OP_SGE: p = CmpInst::ICMP_SGE; break;
      }
      storeReg(dst, B.CreateZExt(B.CreateICmp(p, va, vb), i64));
      finish(pc4);
      continue;
    }
    }
    storeReg(dst, B.CreateZExt(r, i64));     // keep the 64-bit lane zero-extended
    finish(pc4);
  }

  B.SetInsertPoint(bad);
  B.CreateUnreachable();
  return PreservedAnalyses::none();
}
