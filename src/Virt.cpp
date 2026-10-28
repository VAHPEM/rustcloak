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
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/IR/Dominators.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <map>
#include <numeric>
#include <string>
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
  OP_PUSHARG = 36,// argbuf[argn++] = reg[a]   (stage one call argument)
  OP_CALL = 37,   // reg[dst] = calleetable[a](argbuf...); argn = 0   (a = callee index)
  // Only emitted for a NESTED (layer>0) pass, where the function being virtualized is itself an
  // interpreter and so references data globals and has stack allocas (both left native at layer 0):
  OP_GLOBAL = 38, // reg[dst] = &globaltable[a]      (address of a referenced data global)
  OP_ALLOCA = 39, // reg[dst] = alloca i8 x pool[a|b<<8]   (a fixed-size stack allocation)
  // scalar float (f32/f64): the lane holds the value's raw bits. Width code 2=f32, 3=f64.
  OP_FADD = 40, OP_FSUB = 41, OP_FMUL = 42, OP_FDIV = 43, OP_FNEG = 44,
  OP_FEQ = 45, OP_FLT = 46, OP_FLE = 47, OP_FGT = 48, OP_FGE = 49, OP_FNE = 50,
  // conversions: SITOFP/FPTOSI encode (int i32/i64, float f32/f64) in the two width bits
  // (bit1=int width 0:i32/1:i64, bit0=float width 0:f32/1:f64); FPEXT is f32->f64, FPTRUNC f64->f32.
  OP_SITOFP = 51, OP_FPTOSI = 52, OP_FPEXT = 53, OP_FPTRUNC = 54,
};

static uint8_t wcodeOf(unsigned bits) {
  return bits == 8 ? 0 : bits == 16 ? 1 : bits == 32 ? 2 : 3;
}
// inverse of wcodeOf: a 2-bit code -> the width whose wcodeOf is that code (for encoding conversions).
static const unsigned ENCW[4] = {8, 16, 32, 64};

struct VI {
  uint8_t op, dst = 0, a = 0, b = 0;
  BasicBlock *tgt = nullptr;
};

struct Prog {
  std::vector<uint64_t> consts;
  DenseMap<Value *, unsigned> slot;
  // uint64_t-keyed: std::map (not DenseMap) because the constant value may be ~0ull or ~0ull-1,
  // which are DenseMap's reserved empty/tombstone keys -- an i64 -1/-2 literal would assert.
  std::map<uint64_t, unsigned> cpoolIdx, creg;
  std::vector<unsigned> temps;          // PHI copy temporaries
  unsigned gepTmp = 0;                   // one scratch reg for GEP address arithmetic
  unsigned nreg = 0;
  // nested-layer only: referenced data globals and their registers (see OP_GLOBAL)
  std::vector<GlobalVariable *> globals;
  DenseMap<GlobalVariable *, unsigned> gslot;
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

// A value the VM can hold in an i64 register: a small-enough integer, or a pointer. Used for call
// ABI (integer/pointer args go in integer registers through the uniform thunk) -- NOT widened to
// float, which would break the ABI of a virtualized call.
static bool isRegTy(Type *T) {
  return (T->isIntegerTy() && T->getIntegerBitWidth() <= 64) || T->isPointerTy();
}
// A value a VM lane can hold: isRegTy plus scalar f32/f64 (kept as raw bits in the lane).
static bool isLaneTy(Type *T) { return isRegTy(T) || T->isFloatTy() || T->isDoubleTy(); }

static bool okOperand(Value *v, bool allowGlobal = false) {
  if (allowGlobal && isa<GlobalVariable>(v))
    return true;                         // nested layer: data-global address via OP_GLOBAL
  return isa<Argument>(v) || isa<Instruction>(v) || isa<ConstantInt>(v) || isa<ConstantFP>(v) ||
         isa<UndefValue>(v) || isa<ConstantPointerNull>(v);
}

// A direct call we can virtualize: a known, non-vararg, non-intrinsic callee, at most 6 integer/
// pointer arguments (all passed in registers on SysV/AAPCS, so a uniform i64(i64x6) thunk is ABI-
// safe), returning an integer/pointer/void. Float/vector args or >6 args -> leave the function
// native.
// The VM's width-sensitive opcodes carry a 2-bit width code that decodes to {8,16,32,64}. An
// integer of any other width would be decoded as 64-bit and mis-handled, so such ops are only
// virtualized at these widths.
static bool stdWidth(unsigned w) { return w == 8 || w == 16 || w == 32 || w == 64; }

static Function *virtCallee(CallInst *ci) {
  if (ci->isInlineAsm())
    return nullptr;
  Function *callee = ci->getCalledFunction();
  if (!callee || callee->isIntrinsic() || callee->isVarArg() || ci->arg_size() > 6)
    return nullptr;
  for (Value *a : ci->args())
    if (!isRegTy(a->getType()))
      return nullptr;
  Type *rt = ci->getType();
  // Returned through a uniform i64 thunk: void and pointer are fine as-is; a narrow int is re-zero-
  // extended by the CALL handler from its (standard) width. A non-standard int return width has no
  // width-code slot, so leave such a callee native.
  if (rt->isVoidTy() || rt->isPointerTy())
    return callee;
  if (rt->isIntegerTy() && stdWidth(rt->getIntegerBitWidth()))
    return callee;
  return nullptr;
}

// ---- selective virtualization --------------------------------------------------------------
// Virtualization is the strongest transform but also the most expensive (~an order of magnitude
// slower for the virtualized function). Applying it to EVERY eligible function therefore taxes the
// whole program for protection only a few sensitive routines (licence checks, crypto, key schedules)
// actually need. Selective mode scopes the VM to where it matters:
//
//   default (RUSTCLOAK_VM=1)      every eligible function (unchanged behaviour)
//   RUSTCLOAK_VM_SELECTIVE=1      only functions whose name looks sensitive (heuristic below)
//   RUSTCLOAK_VM_ONLY=a,b,...     only functions whose name contains one of these substrings
//   RUSTCLOAK_VM_SKIP=a,b,...     never these (a denylist; applies in every mode)
//   __attribute__((annotate("rustcloak_vm")))  force-virtualize this function in any mode
//   RUSTCLOAK_VM_RATIO=P          of those otherwise chosen, keep a seeded ~P% (0..100)
static std::vector<std::string> splitList(const char *e) {
  std::vector<std::string> out;
  if (!e) return out;
  std::string s(e), cur;
  for (char c : s) {
    if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
    else cur += (char)std::tolower((unsigned char)c);
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}
static bool containsAny(StringRef name, const std::vector<std::string> &pats) {
  std::string lo = name.lower();
  for (const std::string &p : pats)
    if (lo.find(p) != std::string::npos)
      return true;
  return false;
}
// Name heuristic: substrings common to security-sensitive routines. Matched case-insensitively on
// the (possibly mangled) symbol name, so `license_check`, `aes_encrypt`, `keyschedule` all hit.
static bool sensitiveName(StringRef name) {
  static const std::vector<std::string> kw = {
    "check", "verif", "valid", "licen", "crypt", "cipher", "encrypt", "decrypt", "key",
    "hash", "auth", "sign", "secret", "token", "passw", "serial", "schedule", "mac", "hmac"};
  return containsAny(name, kw);
}
// A function carries __attribute__((annotate("want"))) when @llvm.global.annotations has an entry
// whose first field is this function and whose string field equals `want`.
static bool hasFnAnnotation(Function &F, StringRef want) {
  GlobalVariable *GA = F.getParent()->getGlobalVariable("llvm.global.annotations");
  if (!GA || !GA->hasInitializer())
    return false;
  auto *arr = dyn_cast<ConstantArray>(GA->getInitializer());
  if (!arr)
    return false;
  for (Value *op : arr->operands()) {
    auto *cs = dyn_cast<ConstantStruct>(op);
    if (!cs || cs->getNumOperands() < 2)
      continue;
    if (cs->getOperand(0)->stripPointerCasts() != &F)
      continue;
    auto *strGV = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
    if (!strGV || !strGV->hasInitializer())
      continue;
    if (auto *cda = dyn_cast<ConstantDataArray>(strGV->getInitializer()))
      if (cda->isCString() && cda->getAsCString() == want)
        return true;
  }
  return false;
}
static bool selectedForVirt(Function &F) {
  StringRef name = F.getName();
  static const std::vector<std::string> skip = splitList(std::getenv("RUSTCLOAK_VM_SKIP"));
  static const std::vector<std::string> only = splitList(std::getenv("RUSTCLOAK_VM_ONLY"));
  static const bool selective = std::getenv("RUSTCLOAK_VM_SELECTIVE") != nullptr;
  static const int ratio = []() {
    const char *e = std::getenv("RUSTCLOAK_VM_RATIO");
    return e ? std::atoi(e) : 100;
  }();

  if (containsAny(name, skip))
    return false;                          // denylist always wins
  if (hasFnAnnotation(F, "rustcloak_vm"))
    return true;                           // explicit opt-in bypasses selective/only/ratio
  bool pick;
  if (!only.empty())
    pick = containsAny(name, only);        // allowlist mode
  else if (selective)
    pick = sensitiveName(name);            // heuristic mode
  else
    pick = true;                           // default: every eligible function
  if (!pick)
    return false;
  if (ratio < 100)                         // seeded thinning, reproducible for a fixed seed
    if ((int)(rustcloak::rng(("vmratio:" + name.str()))() % 100) >= ratio)
      return false;
  return true;
}

// `nested` is true for a layer>0 pass, where F is itself an interpreter: it then also accepts static
// stack allocas (OP_ALLOCA) and references to data globals (OP_GLOBAL), which layer 0 leaves native.
static bool eligible(Function &F, bool nested = false) {
  if (F.isDeclaration() || F.isVarArg())
    return false;
  for (Argument &A : F.args())
    if (!isLaneTy(A.getType()))
      return false;
  for (BasicBlock &BB : F) {
    Instruction *term = BB.getTerminator();
    if (auto *ret = dyn_cast<ReturnInst>(term)) {
      Value *rv = ret->getReturnValue();
      if (rv && !isLaneTy(rv->getType()))
        return false;                    // int<=64, pointer, float, or void return
    } else if (!isa<BranchInst>(term)) {
      return false;
    }
    for (Instruction &I : BB) {
      if (!I.getType()->isVoidTy() && !isLaneTy(I.getType()))
        return false;
      bool ok = false;
      if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
        if (bo->getType()->isFloatTy() || bo->getType()->isDoubleTy()) {
          unsigned op = bo->getOpcode();        // scalar float arithmetic (bit-identical to native)
          ok = op == Instruction::FAdd || op == Instruction::FSub ||
               op == Instruction::FMul || op == Instruction::FDiv;
        } else {
          unsigned w = bo->getType()->isIntegerTy() ? bo->getType()->getIntegerBitWidth() : 0;
          bool bitwise = bo->getOpcode() == Instruction::And ||
                         bo->getOpcode() == Instruction::Or ||
                         bo->getOpcode() == Instruction::Xor;
          // arithmetic/shift must be a standard width (correctly width-decoded); bitwise ops are
          // correct at any width <= 64 on zero-extended lanes, so boolean i1 and/or/xor stay in.
          ok = stdWidth(w) || (bitwise && w >= 1 && w <= 64);
        }
      } else if (auto *un = dyn_cast<UnaryOperator>(&I)) {
        ok = un->getOpcode() == Instruction::FNeg &&
             (un->getType()->isFloatTy() || un->getType()->isDoubleTy());
      } else if (auto *fc = dyn_cast<FCmpInst>(&I)) {
        auto pr = fc->getPredicate();
        bool okp = pr == CmpInst::FCMP_OEQ || pr == CmpInst::FCMP_OLT || pr == CmpInst::FCMP_OLE ||
                   pr == CmpInst::FCMP_OGT || pr == CmpInst::FCMP_OGE || pr == CmpInst::FCMP_ONE;
        Type *ot = fc->getOperand(0)->getType();
        ok = okp && (ot->isFloatTy() || ot->isDoubleTy());
      } else if (auto *s2f = dyn_cast<SIToFPInst>(&I)) {
        Type *st = s2f->getOperand(0)->getType(), *dt = s2f->getType();
        ok = st->isIntegerTy() && (st->getIntegerBitWidth() == 32 || st->getIntegerBitWidth() == 64) &&
             (dt->isFloatTy() || dt->isDoubleTy());
      } else if (auto *f2s = dyn_cast<FPToSIInst>(&I)) {
        Type *st = f2s->getOperand(0)->getType(), *dt = f2s->getType();
        ok = (st->isFloatTy() || st->isDoubleTy()) && dt->isIntegerTy() &&
             (dt->getIntegerBitWidth() == 32 || dt->getIntegerBitWidth() == 64);
      } else if (isa<FPExtInst>(&I)) {
        ok = I.getOperand(0)->getType()->isFloatTy() && I.getType()->isDoubleTy();
      } else if (isa<FPTruncInst>(&I)) {
        ok = I.getOperand(0)->getType()->isDoubleTy() && I.getType()->isFloatTy();
      } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        unsigned w = ic->getOperand(0)->getType()->isIntegerTy()
                         ? ic->getOperand(0)->getType()->getIntegerBitWidth() : 0;
        bool eqne = ic->getPredicate() == CmpInst::ICMP_EQ ||
                    ic->getPredicate() == CmpInst::ICMP_NE;
        // standard widths for any predicate; i1 only for eq/ne (a non-standard width would be
        // compared at 64-bit, which is wrong for signed predicates).
        ok = cmpBase(ic->getPredicate()) && (stdWidth(w) || (w == 1 && eqne));
      } else if (auto *se = dyn_cast<SelectInst>(&I)) {
        ok = se->getCondition()->getType()->isIntegerTy(1) && isLaneTy(se->getType());
      } else if (isa<TruncInst>(&I) || isa<ZExtInst>(&I)) {
        // trunc -> AND with a mask (any target width); zext -> MOV (copy of a clean lane).
        ok = I.getType()->isIntegerTy() && I.getOperand(0)->getType()->isIntegerTy();
      } else if (auto *se2 = dyn_cast<SExtInst>(&I)) {
        // sext truncates to the SOURCE width (width-encoded) then sign-extends, so the source
        // width must be standard.
        ok = se2->getType()->isIntegerTy() && se2->getOperand(0)->getType()->isIntegerTy() &&
             stdWidth(se2->getOperand(0)->getType()->getIntegerBitWidth());
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
        Type *lt = ld->getType();            // float loads reuse the integer load of the same width
        ok = !ld->isAtomic() && !ld->isVolatile() &&
             ((lt->isIntegerTy() && stdWidth(lt->getIntegerBitWidth())) ||
              lt->isFloatTy() || lt->isDoubleTy());
      } else if (auto *st = dyn_cast<StoreInst>(&I)) {
        Type *vt = st->getValueOperand()->getType();
        ok = !st->isAtomic() && !st->isVolatile() &&
             ((vt->isIntegerTy() && stdWidth(vt->getIntegerBitWidth())) ||
              vt->isFloatTy() || vt->isDoubleTy());
      } else if (isa<PHINode>(&I)) {
        ok = isLaneTy(I.getType());
      } else if (auto *ci = dyn_cast<CallInst>(&I)) {
        ok = virtCallee(ci) != nullptr;
      } else if (auto *al = dyn_cast<AllocaInst>(&I)) {
        ok = nested && al->isStaticAlloca();   // fixed-size stack slot, nested layer only
      } else if (isa<ReturnInst>(&I) || isa<BranchInst>(&I)) {
        ok = true;
      }
      if (!ok)
        return false;
      auto *callI = dyn_cast<CallInst>(&I);
      for (Value *op : I.operands()) {
        if (isa<BasicBlock>(op))
          continue;
        if (callI && op == callI->getCalledOperand())
          continue;                      // the callee (a Function) is handled via the callee table
        if (!okOperand(op, nested))
          return false;                  // globals / constexprs / float consts -> native
      }
    }
  }
  return true;
}

// Selective inter-function virtualization (RUSTCLOAK_VM_INLINE): inline small, internal, leaf,
// virt-eligible callees into F before it is virtualized, so their operations become part of F's
// bytecode and the call boundary disappears. Sound (InlineFunction preserves semantics) and
// bounded (leaf-only -> no recursion, size-capped, fixed inline budget).
static void inlineTinyCallees(Function &F) {
  unsigned budget = 8;
  bool changed = true;
  while (changed && budget) {
    changed = false;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *ci = dyn_cast<CallInst>(&I);
        if (!ci || ci->isInlineAsm())
          continue;
        Function *cal = ci->getCalledFunction();
        if (!cal || cal == &F || cal->isDeclaration() || cal->isVarArg())
          continue;
        if (!cal->hasInternalLinkage() && !cal->hasPrivateLinkage())
          continue;
        unsigned ninst = 0;
        bool leaf = true;
        for (BasicBlock &CB : *cal)
          for (Instruction &CI : CB) {
            ninst++;
            if (isa<CallInst>(CI) || isa<InvokeInst>(CI))
              leaf = false;               // leaf only: no recursion, no call chains
          }
        if (!leaf || ninst > 30 || !eligible(*cal))
          continue;
        InlineFunctionInfo IFI;
        if (InlineFunction(*ci, IFI).isSuccess()) {
          changed = true;
          --budget;
        }
        break;                            // inlining invalidated the iterators; rescan
      }
      if (changed)
        break;
    }
  }
}

// Partial (block-level) virtualization (RUSTCLOAK_VM_PARTIAL): for a function that is NOT wholly
// virt-eligible, outline ONE clean, single-successor block region into its own internal function
// with LLVM's CodeExtractor. The virt pass then virtualizes that outlined function (if it passes
// eligibility), so a PART of a function that would otherwise stay entirely native runs under the VM.
// CodeExtractor is semantics-preserving and the virt pass still gates on eligible(), so this is
// correctness-safe by construction regardless of which block is chosen; the worst case is an outlined
// function that stays native (no benefit, no harm). The region is kept simple -- a non-entry block
// with an unconditional-branch terminator, no PHIs, no allocas/invokes, >=4 real instructions -- so
// the outlined function returns void with scalar/pointer in/out parameters the VM already handles.
static Function *outlineEligibleRegion(Function &F) {
  DominatorTree DT(F);
  for (BasicBlock &BB : F) {
    if (&BB == &F.getEntryBlock() || BB.isEHPad())
      continue;
    auto *br = dyn_cast<BranchInst>(BB.getTerminator());
    if (!br || !br->isUnconditional())        // single successor -> outlined fn returns void
      continue;
    if (isa<PHINode>(BB.front()))             // avoid region-entry PHIs
      continue;
    unsigned n = 0;
    bool bad = false;
    for (Instruction &I : BB) {
      if (I.isTerminator())
        continue;
      if (isa<AllocaInst>(I) || I.isEHPad() || isa<InvokeInst>(I)) { bad = true; break; }
      n++;
    }
    if (bad || n < 4)
      continue;
    SmallVector<BasicBlock *, 1> rb{&BB};
    CodeExtractor CE(rb, &DT);
    if (!CE.isEligible())
      continue;
    CodeExtractorAnalysisCache CEAC(F);
    if (Function *G = CE.extractCodeRegion(CEAC)) {
      G->setLinkage(GlobalValue::InternalLinkage);
      G->addFnAttr("rc-outlined");            // so PartialOutlinePass does not re-process it
      return G;
    }
  }
  return nullptr;
}

} // namespace

// One virtualization layer: rebuild F as a bytecode interpreter. `layer` seeds a distinct opcode map
// and operand keys, so a nested second pass (layer 1, over the layer-0 interpreter) gets a different
// VM instruction set. Returns true if F was virtualized, false if it was left unchanged (ineligible).
static bool virtualizeOnce(Function &F, unsigned layer) {
  bool nested = layer > 0;
  if (!eligible(F, nested))
    return false;

  // Per-build, per-function opcode encoding with SYNONYMS. The low 6 bits of the opcode byte are a
  // slot; each logical base owns one or more slots (frequent ops own several), and emit() picks a
  // random slot of the op each time -- so no single byte dominates a frequency count and an analyst
  // cannot tag "the most common opcode" as ADD. `dec` maps every slot back to its logical base; the
  // width still rides in the top two bits. The layout is seeded, so two builds (or two functions)
  // share no instruction set.
  std::mt19937_64 encRng =
      rustcloak::rng(("vmenc:" + std::to_string(layer) + ":" + F.getName()).str());
  const unsigned NBASE = OP_ALLOCA + 1;  // logical bases 0..OP_ALLOCA
  auto weightOf = [](unsigned b) -> unsigned {
    switch (b) {
    case OP_MOV: case OP_CONST: case OP_ADD: case OP_SUB:
    case OP_XOR: case OP_AND: case OP_OR: case OP_LOAD: case OP_STORE: return 3;
    default: return 1;
    }
  };
  std::vector<uint8_t> assign;           // slot -> logical base; every base appears at least once
  for (unsigned b = 0; b < NBASE; b++)
    assign.push_back((uint8_t)b);
  std::vector<uint8_t> extra;            // weighted extra synonym slots for the frequent ops
  for (unsigned b = 0; b < NBASE; b++)
    for (unsigned w = 1; w < weightOf(b); w++)
      extra.push_back((uint8_t)b);
  std::shuffle(extra.begin(), extra.end(), encRng);
  for (uint8_t b : extra) {
    if (assign.size() >= 64) break;
    assign.push_back(b);
  }
  while (assign.size() < 64)             // pad any remaining slots with random synonyms
    assign.push_back((uint8_t)(encRng() % NBASE));
  std::shuffle(assign.begin(), assign.end(), encRng);
  std::array<uint8_t, 64> dec;           // slot -> logical base
  std::array<std::vector<uint8_t>, 64> syn;   // logical base -> its slots
  for (unsigned s = 0; s < 64; s++) {
    dec[s] = assign[s];
    syn[assign[s]].push_back((uint8_t)s);
  }
  auto pickSlot = [&](uint8_t base) -> uint8_t {
    auto &v = syn[base];
    return v[encRng() % v.size()];
  };
  // the three operand bytes (dst, a, b) are XOR-encrypted with a per-build/per-function key, so the
  // whole 4-byte instruction -- not just the opcode -- is build-specific; the interpreter decrypts
  // each operand after fetch. (Register indices, pool indices and branch targets are all hidden.)
  std::mt19937_64 kg =
      rustcloak::rng(("vmkey:" + std::to_string(layer) + ":" + F.getName()).str());
  uint8_t kd = kg() & 0xff, ka = kg() & 0xff, kb = kg() & 0xff;
  // Anti-tamper (RUSTCLOAK_VM_INTEGRITY): the interpreter hashes its own bytecode at run time and
  // folds the hash into these operand keys, so patching any bytecode byte silently corrupts every
  // operand decode rather than tripping a comparison a patcher could NOP. Off by default.
  bool integrity = rustcloak::flagOn("RUSTCLOAK_VM_INTEGRITY");
  // RUSTCLOAK_VM_JMP: dispatch through an encrypted block-address table reached by indirectbr,
  // instead of a bare switch a VM lifter can pattern-match (see the dispatch emission below).
  bool jmp = rustcloak::flagOn("RUSTCLOAK_VM_JMP");

  SplitAllCriticalEdges(F);              // so PHI copies can live at predecessors
  // PHI copies are emitted only on UNCONDITIONAL-branch edges (see phiCopies, used only in the JMP
  // arm of the terminator emission). SplitAllCriticalEdges splits conditional edges into multi-pred
  // PHI blocks, but a conditional edge into a SINGLE-predecessor PHI block is not "critical" and is
  // left intact -- and would then get no PHI copy, leaving the PHI's VM register uninitialised. Split
  // those too, so every PHI predecessor ends in an unconditional branch. (Rare in optimized IR --
  // simplifycfg folds single-entry PHIs -- but reachable with hand-written IR or explicit -passes.)
  {
    std::vector<std::pair<BranchInst *, BasicBlock *>> edges;
    for (BasicBlock &BB : F) {
      auto *br = dyn_cast<BranchInst>(BB.getTerminator());
      if (!br || !br->isConditional() || br->getSuccessor(0) == br->getSuccessor(1))
        continue;                        // skip a degenerate `br c, X, X` (effectively uncond)
      for (BasicBlock *succ : successors(&BB))
        if (!succ->phis().empty())
          edges.push_back({br, succ});
    }
    // Insert a fresh block ON each such edge (not via SplitEdge, which for a single-predecessor
    // successor splits the SUCCESSOR and leaves the conditional edge reaching the PHI directly). The
    // new block branches unconditionally to the real successor, so phiCopies runs there.
    for (auto &e : edges) {
      BranchInst *br = e.first;
      BasicBlock *succ = e.second, *src = br->getParent();
      BasicBlock *mid = BasicBlock::Create(F.getContext(), "", &F, succ);
      BranchInst::Create(succ, mid);
      br->replaceSuccessorWith(succ, mid);
      for (PHINode &phi : succ->phis())
        phi.replaceIncomingBlockWith(src, mid);
    }
  }

  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  const DataLayout &DL = M.getDataLayout();
  Type *i64 = Type::getInt64Ty(Ctx);

  auto widthOf = [](Value *v) -> unsigned {
    Type *t = v->getType();
    if (t->isIntegerTy()) return t->getIntegerBitWidth();
    if (t->isFloatTy())   return 32;                          // f32 lane width
    if (t->isDoubleTy())  return 64;                          // f64 lane width
    return 64;                                                // pointers: 64-bit lane
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
      if (!I.isTerminator() && !I.getType()->isVoidTy() && isLaneTy(I.getType()))
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
      for (Value *op : I.operands()) {
        if (auto *ci = dyn_cast<ConstantInt>(op))
          wantConst(ci->getZExtValue());
        else if (auto *cf = dyn_cast<ConstantFP>(op))
          wantConst(cf->getValueAPF().bitcastToAPInt().getZExtValue());  // float literal as raw bits
      }
      if (auto *tr = dyn_cast<TruncInst>(&I)) {
        // A trunc lowers to AND with a width mask; collect that mask HERE, before the OP_CONST ops
        // are emitted below -- a mask first requested during emission would get a register but no
        // OP_CONST to initialise it, i.e. an uninitialised register. (bug fix)
        unsigned w = tr->getType()->getIntegerBitWidth();
        wantConst(w >= 64 ? ~0ull : ((1ull << w) - 1));
      }
      if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        // Mirror lowerGEP exactly: a stride multiply per VARIABLE index, plus ONE add of the folded
        // constant offset (constant indices and struct-field offsets). Both the strides and that
        // folded offset are read from the pool, so both must be collected here. (Previously only
        // strides were, and the folded offset was looked up with operator[], silently inserting 0
        // -> register 0 -> wrong address.) (bug fix)
        uint64_t constOff = 0;
        for (auto it = gep_type_begin(gep), e = gep_type_end(gep); it != e; ++it) {
          if (StructType *STy = it.getStructTypeOrNull()) {
            unsigned f = cast<ConstantInt>(it.getOperand())->getZExtValue();
            constOff += DL.getStructLayout(STy)->getElementOffset(f);
            continue;
          }
          uint64_t stride = DL.getTypeAllocSize(it.getIndexedType()).getFixedValue();
          if (auto *ci = dyn_cast<ConstantInt>(it.getOperand()))
            constOff += (uint64_t)ci->getSExtValue() * stride;   // folded, not a pool stride
          else
            wantConst(stride);                                   // runtime index: stride needed
        }
        if (constOff)
          wantConst(constOff);
      }
    }
  // nested layer: a register per referenced data global (OP_GLOBAL fills it), and each static
  // alloca's byte size in the pool (OP_ALLOCA reads it). Collected before the OP_CONST prologue.
  if (nested)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        for (Value *op : I.operands())
          if (auto *gv = dyn_cast<GlobalVariable>(op))
            if (!P.gslot.count(gv)) {
              P.gslot[gv] = P.nreg++;
              P.globals.push_back(gv);
            }
        if (auto *al = dyn_cast<AllocaInst>(&I))
          if (auto sz = al->getAllocationSize(DL))
            wantConst(sz->getFixedValue());
      }
  wantConst(0);
  for (unsigned i = 0; i < maxPhi; i++)
    P.temps.push_back(P.nreg++);
  P.gepTmp = P.nreg++;
  unsigned voidScratch = P.nreg++;       // reg[dst] for a call whose result is void/unused

  // the callees reached by CALL opcodes, as a per-function function-pointer table
  std::vector<Function *> callees;
  DenseMap<Function *, unsigned> calleeIdx;
  for (BasicBlock &BB : F)
    for (Instruction &I : BB)
      if (auto *ci = dyn_cast<CallInst>(&I))
        if (Function *c = virtCallee(ci))
          if (!calleeIdx.count(c)) {
            calleeIdx[c] = (unsigned)callees.size();
            callees.push_back(c);
          }
  if (P.nreg > 256 || P.consts.size() > 0xffff || callees.size() > 256)
    return false;

  auto regOf = [&](Value *v) -> unsigned {
    if (auto *ci = dyn_cast<ConstantInt>(v))
      return P.creg[ci->getZExtValue()];
    if (auto *cf = dyn_cast<ConstantFP>(v))
      return P.creg[cf->getValueAPF().bitcastToAPInt().getZExtValue()];
    if (isa<UndefValue>(v) || isa<ConstantPointerNull>(v))
      return P.creg[0];
    if (auto *gv = dyn_cast<GlobalVariable>(v))
      return P.gslot[gv];                // nested layer: data global's address register
    return P.slot[v];
  };

  std::vector<VI> code;
  auto emit = [&](uint8_t base, unsigned width, unsigned dst, unsigned a, unsigned b,
                  BasicBlock *tgt = nullptr) {
    code.push_back(VI{(uint8_t)(pickSlot(base) | (wcodeOf(width) << 6)), (uint8_t)dst,
                      (uint8_t)a, (uint8_t)b, tgt});
  };
  for (auto &kv : P.creg)
    emit(OP_CONST, 64, kv.second, P.cpoolIdx[kv.first] & 0xff, P.cpoolIdx[kv.first] >> 8);
  for (unsigned gi = 0; gi < P.globals.size(); gi++)   // nested: load each data global's address
    emit(OP_GLOBAL, 64, P.gslot[P.globals[gi]], gi & 0xff, gi >> 8);

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
      unsigned d = (!I.getType()->isVoidTy() && isLaneTy(I.getType())) ? regOf(&I) : 0;
      if (auto *bo = dyn_cast<BinaryOperator>(&I)) {
        if (bo->getType()->isFloatTy() || bo->getType()->isDoubleTy()) {
          static const DenseMap<unsigned, uint8_t> FM = {
            {Instruction::FAdd, OP_FADD}, {Instruction::FSub, OP_FSUB},
            {Instruction::FMul, OP_FMUL}, {Instruction::FDiv, OP_FDIV}};
          auto f = FM.find(bo->getOpcode());
          if (f == FM.end())
            return false;
          emit(f->second, widthOf(bo), d, regOf(bo->getOperand(0)), regOf(bo->getOperand(1)));
        } else {
          static const DenseMap<unsigned, uint8_t> M = {
            {Instruction::Add, OP_ADD}, {Instruction::Sub, OP_SUB}, {Instruction::Mul, OP_MUL},
            {Instruction::And, OP_AND}, {Instruction::Or, OP_OR}, {Instruction::Xor, OP_XOR},
            {Instruction::Shl, OP_SHL}, {Instruction::LShr, OP_LSHR}, {Instruction::AShr, OP_ASHR},
            {Instruction::UDiv, OP_UDIV}, {Instruction::SDiv, OP_SDIV},
            {Instruction::URem, OP_UREM}, {Instruction::SRem, OP_SREM}};
          auto f = M.find(bo->getOpcode());
          if (f == M.end())
            return false;
          emit(f->second, widthOf(bo), d, regOf(bo->getOperand(0)), regOf(bo->getOperand(1)));
        }
      } else if (auto *un = dyn_cast<UnaryOperator>(&I)) {    // FNeg
        emit(OP_FNEG, widthOf(un), d, regOf(un->getOperand(0)), 0);
      } else if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        emit(cmpBase(ic->getPredicate()), widthOf(ic->getOperand(0)), d,
             regOf(ic->getOperand(0)), regOf(ic->getOperand(1)));
      } else if (auto *fc = dyn_cast<FCmpInst>(&I)) {
        static const DenseMap<unsigned, uint8_t> FC = {
          {CmpInst::FCMP_OEQ, OP_FEQ}, {CmpInst::FCMP_OLT, OP_FLT}, {CmpInst::FCMP_OLE, OP_FLE},
          {CmpInst::FCMP_OGT, OP_FGT}, {CmpInst::FCMP_OGE, OP_FGE}, {CmpInst::FCMP_ONE, OP_FNE}};
        auto f = FC.find(fc->getPredicate());
        if (f == FC.end())
          return PreservedAnalyses::all();
        emit(f->second, widthOf(fc->getOperand(0)), d,
             regOf(fc->getOperand(0)), regOf(fc->getOperand(1)));
      } else if (auto *s2f = dyn_cast<SIToFPInst>(&I)) {
        unsigned enc = (s2f->getOperand(0)->getType()->getIntegerBitWidth() == 64 ? 2u : 0u) |
                       (s2f->getType()->isDoubleTy() ? 1u : 0u);
        emit(OP_SITOFP, ENCW[enc], d, regOf(s2f->getOperand(0)), 0);
      } else if (auto *f2s = dyn_cast<FPToSIInst>(&I)) {
        unsigned enc = (f2s->getType()->getIntegerBitWidth() == 64 ? 2u : 0u) |
                       (f2s->getOperand(0)->getType()->isDoubleTy() ? 1u : 0u);
        emit(OP_FPTOSI, ENCW[enc], d, regOf(f2s->getOperand(0)), 0);
      } else if (isa<FPExtInst>(&I)) {
        emit(OP_FPEXT, 64, d, regOf(I.getOperand(0)), 0);
      } else if (isa<FPTruncInst>(&I)) {
        emit(OP_FPTRUNC, 64, d, regOf(I.getOperand(0)), 0);
      } else if (auto *se = dyn_cast<SelectInst>(&I)) {
        emit(OP_MOV, 64, d, regOf(se->getFalseValue()), 0);
        emit(OP_CMOVNZ, 64, d, regOf(se->getCondition()), regOf(se->getTrueValue()));
      } else if (isa<ZExtInst>(&I)) {
        // values are kept zero-extended in their 64-bit lane, so a zext is just a copy
        emit(OP_MOV, 64, d, regOf(I.getOperand(0)), 0);
      } else if (isa<SExtInst>(&I)) {
        emit(OP_SEXT, widthOf(I.getOperand(0)), d, regOf(I.getOperand(0)), 0);
      } else if (auto *tr = dyn_cast<TruncInst>(&I)) {
        unsigned w = widthOf(tr);          // mask was pre-collected in the constant-gather pass
        emit(OP_AND, 64, d, regOf(tr->getOperand(0)), P.creg[w >= 64 ? ~0ull : ((1ull << w) - 1)]);
      } else if (isa<PtrToIntInst>(&I) || isa<IntToPtrInst>(&I) || isa<BitCastInst>(&I)) {
        emit(OP_MOV, 64, d, regOf(I.getOperand(0)), 0);
      } else if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        lowerGEP(gep, d);
      } else if (auto *ld = dyn_cast<LoadInst>(&I)) {
        Type *lt = ld->getType();
        unsigned lw = lt->isIntegerTy() ? lt->getIntegerBitWidth() : (lt->isFloatTy() ? 32u : 64u);
        emit(OP_LOAD, lw, d, regOf(ld->getPointerOperand()), 0);   // float: load the bits (same width)
      } else if (auto *st = dyn_cast<StoreInst>(&I)) {
        Type *vt = st->getValueOperand()->getType();
        unsigned sw = vt->isIntegerTy() ? vt->getIntegerBitWidth() : (vt->isFloatTy() ? 32u : 64u);
        emit(OP_STORE, sw, 0, regOf(st->getPointerOperand()), regOf(st->getValueOperand()));
      } else if (auto *ci = dyn_cast<CallInst>(&I)) {
        for (Value *a : ci->args())          // stage each argument, then call
          emit(OP_PUSHARG, 64, 0, regOf(a), 0);
        unsigned rd = ci->getType()->isVoidTy() ? voidScratch : d;
        // Carry the return width in the opcode's width field so the handler can re-zero-extend a
        // narrow int return (the ABI leaves the high bits of the return register undefined).
        // Pointer/i64/void -> width 64 (no masking). (bug fix)
        unsigned callw = 64;
        if (ci->getType()->isIntegerTy()) {
          unsigned rw = ci->getType()->getIntegerBitWidth();
          if (rw == 8 || rw == 16 || rw == 32) callw = rw;
        }
        emit(OP_CALL, callw, rd, calleeIdx[ci->getCalledFunction()], 0);
      } else if (auto *al = dyn_cast<AllocaInst>(&I)) {   // nested layer only
        unsigned ci = P.cpoolIdx[al->getAllocationSize(DL)->getFixedValue()];
        emit(OP_ALLOCA, 64, d, ci & 0xff, ci >> 8);
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

  // Branch/jump targets are encoded in two bytes (offset <= 0xffff). A larger bytecode would
  // silently truncate them, so leave such a (large) function native. (bug fix)
  if (code.size() * 4 > 0xffff)
    return false;

  std::vector<uint8_t> bytes;
  bytes.reserve(code.size() * 4);
  for (VI &vi : code) {
    uint8_t a = vi.a, b = vi.b;
    if (vi.tgt) {
      unsigned off = blockStart[vi.tgt] * 4;
      a = off & 0xff;
      b = (off >> 8) & 0xff;
    }
    bytes.insert(bytes.end(), {vi.op, (uint8_t)(vi.dst ^ kd), (uint8_t)(a ^ ka), (uint8_t)(b ^ kb)});
  }

  // FNV-1a-64 over the FINAL bytecode. When integrity is on, the interpreter recomputes this at run
  // time; the XOR of the two is 0 for an intact blob and mixed into the operand keys, so a single
  // flipped byte makes every subsequent operand decode wrong (addresses, register and pool indices,
  // branch targets) and the VM diverges into garbage -- with no integrity-compare branch to patch.
  uint64_t expected = 0xcbf29ce484222325ull;
  for (uint8_t by : bytes) {
    expected ^= by;
    expected *= 0x100000001b3ull;
  }

  // ---- globals -------------------------------------------------------------
  Constant *bcInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(bytes));
  auto *bc = new GlobalVariable(M, bcInit->getType(), false, GlobalValue::InternalLinkage,
                                bcInit, rustcloak::anon("vb"));
  Constant *poolInit = ConstantDataArray::get(Ctx, ArrayRef<uint64_t>(P.consts));
  auto *pool = new GlobalVariable(M, poolInit->getType(), false, GlobalValue::InternalLinkage,
                                  poolInit, rustcloak::anon("vp"));
  // the callee table: a function-pointer array the CALL opcode indexes
  Type *ptrTy = PointerType::get(Ctx, 0);
  ArrayType *ctTy = ArrayType::get(ptrTy, std::max<size_t>(callees.size(), 1));
  GlobalVariable *calleeTable = nullptr;
  if (!callees.empty()) {
    std::vector<Constant *> cv(callees.begin(), callees.end());
    calleeTable = new GlobalVariable(M, ctTy, false, GlobalValue::InternalLinkage,
                                     ConstantArray::get(ctTy, cv), rustcloak::anon("vc"));
  }
  // nested layer: a pointer table of the referenced data globals the OP_GLOBAL opcode indexes
  ArrayType *gtTy = ArrayType::get(ptrTy, std::max<size_t>(P.globals.size(), 1));
  GlobalVariable *globalTable = nullptr;
  if (!P.globals.empty()) {
    std::vector<Constant *> gv(P.globals.begin(), P.globals.end());
    globalTable = new GlobalVariable(M, gtTy, false, GlobalValue::InternalLinkage,
                                     ConstantArray::get(gtTy, gv), rustcloak::anon("vg"));
  }

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
  ArrayType *argbufTy = ArrayType::get(i64, 8);     // staged call arguments + the count
  Value *argbuf = B.CreateAlloca(argbufTy);
  Value *argn = B.CreateAlloca(i64);
  B.CreateStore(B.getInt64(0), argn);
  auto regGEP = [&](Value *idx) { return B.CreateGEP(regsTy, regs, {B.getInt64(0), idx}); };
  for (unsigned i = 0; i < args.size(); i++) {
    Value *v = args[i];
    Type *at = v->getType();
    if (at->isPointerTy())
      v = B.CreatePtrToInt(v, i64);
    else if (at->isFloatTy())
      v = B.CreateZExt(B.CreateBitCast(v, Type::getInt32Ty(Ctx)), i64);  // f32 bits in the lane
    else if (at->isDoubleTy())
      v = B.CreateBitCast(v, i64);                                       // f64 bits in the lane
    else
      v = B.CreateZExt(v, i64);
    B.CreateStore(v, regGEP(B.getInt64(P.slot[args[i]])));
  }
  ArrayType *bcTy = cast<ArrayType>(bcInit->getType());

  // Operand-decryption keys: the per-build constants, unless integrity is on -- then a run-time
  // self-hash of the bytecode is XOR-folded in. `preLoop` is the block that falls into the dispatch
  // loop (entry directly, or the hash epilogue), so the pc PHI's first incoming is correct.
  Value *kdV = B.getInt64(kd), *kaV = B.getInt64(ka), *kbV = B.getInt64(kb);
  BasicBlock *preLoop = entry;
  if (integrity) {
    BasicBlock *hloop = BasicBlock::Create(Ctx, "", &F, loop);
    BasicBlock *hdone = BasicBlock::Create(Ctx, "", &F, loop);
    B.CreateBr(hloop);
    B.SetInsertPoint(hloop);
    PHINode *hi = B.CreatePHI(i64, 2);   // byte index
    PHINode *hh = B.CreatePHI(i64, 2);   // running FNV-1a state
    hi->addIncoming(B.getInt64(0), entry);
    hh->addIncoming(B.getInt64(0xcbf29ce484222325ull), entry);
    LoadInst *hb = B.CreateLoad(i8, B.CreateGEP(bcTy, bc, {B.getInt64(0), hi}));
    hb->setVolatile(true);               // volatile: the hash cannot be constant-folded away
    Value *hhn = B.CreateMul(B.CreateXor(hh, B.CreateZExt(hb, i64)), B.getInt64(0x100000001b3ull));
    Value *hin = B.CreateAdd(hi, B.getInt64(1));
    hh->addIncoming(hhn, hloop);
    hi->addIncoming(hin, hloop);
    B.CreateCondBr(B.CreateICmpULT(hin, B.getInt64(bytes.size())), hloop, hdone);
    B.SetInsertPoint(hdone);
    Value *delta = B.CreateXor(hhn, B.getInt64(expected));   // 0 iff the bytecode is intact
    auto foldByte = [&](uint8_t k, unsigned sh) {
      return B.CreateXor(B.getInt64(k),
                         B.CreateAnd(B.CreateLShr(delta, B.getInt64(sh)), B.getInt64(0xff)));
    };
    kdV = foldByte(kd, 0);
    kaV = foldByte(ka, 8);
    kbV = foldByte(kb, 16);
    B.CreateBr(loop);
    preLoop = hdone;
  } else {
    B.CreateBr(loop);
  }

  B.SetInsertPoint(loop);
  PHINode *pc = B.CreatePHI(i64, 1 + 64);
  pc->addIncoming(B.getInt64(0), preLoop);
  auto bcByte = [&](Value *o) {
    LoadInst *l = B.CreateLoad(i8, B.CreateGEP(bcTy, bc, {B.getInt64(0), o}));
    l->setVolatile(true);
    return l;
  };
  Value *opByte = bcByte(pc);          // opcode is permuted, not XOR-encrypted
  Value *dst = B.CreateXor(B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(1))), i64), kdV);
  Value *ra = B.CreateXor(B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(2))), i64), kaV);
  Value *rb = B.CreateXor(B.CreateZExt(bcByte(B.CreateAdd(pc, B.getInt64(3))), i64), kbV);
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

  ArrayType *poolTy = cast<ArrayType>(poolInit->getType());
  auto finish = [&](Value *nextpc) {
    pc->addIncoming(nextpc, B.GetInsertBlock());
    B.CreateBr(loop);
  };

  // one handler block per present opcode (bodies filled below)
  DenseMap<unsigned, BasicBlock *> hblk;
  for (unsigned ob : present)
    hblk[ob] = BasicBlock::Create(Ctx, "", &F, bad);

  // Dispatch. Default: a bare `switch opByte`. RUSTCLOAK_VM_JMP: an ENCRYPTED JUMP TABLE -- the
  // opcode is run through a per-build affine permutation of 0..255 (A odd => a bijection mod 256) to
  // index a global table of block addresses, and control transfers by `indirectbr`. There is then no
  // switch for a symbolic VM-lifter to recognise as the dispatcher, and the opcode->handler mapping
  // is hidden in the permuted table rather than sitting in readable case labels.
  if (jmp) {
    uint64_t A = (encRng() | 1u) & 0xffu, Bk = encRng() & 0xffu;
    std::vector<Constant *> slots(256, BlockAddress::get(&F, bad));
    for (unsigned ob : present)
      slots[(A * ob + Bk) & 0xff] = BlockAddress::get(&F, hblk[ob]);
    ArrayType *jtTy = ArrayType::get(ptrTy, 256);
    auto *jtab = new GlobalVariable(M, jtTy, true, GlobalValue::InternalLinkage,
                                    ConstantArray::get(jtTy, slots), rustcloak::anon("vj"));
    Value *idx = B.CreateAnd(
        B.CreateAdd(B.CreateMul(B.CreateZExt(opByte, i64), B.getInt64(A)), B.getInt64(Bk)),
        B.getInt64(0xff));
    Value *tp = B.CreateLoad(ptrTy, B.CreateGEP(jtTy, jtab, {B.getInt64(0), idx}));
    IndirectBrInst *ibr = B.CreateIndirectBr(tp, present.size() + 1);
    for (unsigned ob : present)
      ibr->addDestination(hblk[ob]);
    ibr->addDestination(bad);
  } else {
    SwitchInst *sw = B.CreateSwitch(opByte, bad, present.size());
    for (unsigned ob : present)
      sw->addCase(ConstantInt::get(cast<IntegerType>(i8), ob), hblk[ob]);
  }

  static const unsigned WBITS[4] = {8, 16, 32, 64};
  for (unsigned ob : present) {
    uint8_t base = dec[ob & 0x3f];
    unsigned wbits = WBITS[(ob >> 6) & 3];
    Type *iW = IntegerType::get(Ctx, wbits);
    BasicBlock *h = hblk[ob];
    B.SetInsertPoint(h);

    if (base == OP_RETV) { B.CreateRetVoid(); continue; }
    if (base == OP_RET) {
      Value *v = loadReg(ra);
      if (retTy->isPointerTy())
        v = B.CreateIntToPtr(v, retTy);   // the lane holds the address; hand back a pointer
      else if (retTy->isFloatTy())
        v = B.CreateBitCast(B.CreateTrunc(v, Type::getInt32Ty(Ctx)), retTy);
      else if (retTy->isDoubleTy())
        v = B.CreateBitCast(v, retTy);
      else if (retTy->isIntegerTy() && retTy->getIntegerBitWidth() < 64)
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
    if (base == OP_GLOBAL && globalTable) {       // reg[dst] = (i64)&globaltable[tgt]
      Value *gp = B.CreateLoad(ptrTy, B.CreateGEP(gtTy, globalTable, {B.getInt64(0), tgt}));
      storeReg(dst, B.CreatePtrToInt(gp, i64));
      finish(pc4);
      continue;
    }
    if (base == OP_ALLOCA) {                       // reg[dst] = (i64)alloca i8 x pool[tgt]
      LoadInst *szl = B.CreateLoad(i64, B.CreateGEP(poolTy, pool, {B.getInt64(0), tgt}));
      szl->setVolatile(true);
      AllocaInst *mem = B.CreateAlloca(i8, szl);
      mem->setAlignment(Align(16));               // satisfies any i8/i16/i32/i64 lane access
      storeReg(dst, B.CreatePtrToInt(mem, i64));
      finish(pc4);
      continue;
    }
    if (base == OP_PUSHARG) {
      Value *n = B.CreateLoad(i64, argn);
      B.CreateStore(loadReg(ra), B.CreateGEP(argbufTy, argbuf, {B.getInt64(0), n}));
      B.CreateStore(B.CreateAdd(n, B.getInt64(1)), argn);
      finish(pc4);
      continue;
    }
    if (base == OP_CALL && calleeTable) {
      // reg[dst] = calleetable[ra](argbuf[0..5]); a uniform i64(i64x6) thunk is ABI-safe for the
      // <=6 integer/pointer args the eligibility check guarantees.
      Value *fp = B.CreateLoad(ptrTy, B.CreateGEP(ctTy, calleeTable, {B.getInt64(0), ra}));
      FunctionType *thunk = FunctionType::get(i64, {i64, i64, i64, i64, i64, i64}, false);
      SmallVector<Value *, 6> cargs;
      for (unsigned k = 0; k < 6; k++)
        cargs.push_back(B.CreateLoad(i64, B.CreateGEP(argbufTy, argbuf, {B.getInt64(0), B.getInt64(k)})));
      Value *res = B.CreateCall(thunk, fp, cargs);
      if (wbits < 64)                      // narrow int return: re-establish the zero-extended lane
        res = B.CreateZExt(B.CreateTrunc(res, iW), i64);
      storeReg(dst, res);
      B.CreateStore(B.getInt64(0), argn);
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
    // ---- scalar floating point (lane holds raw bits; wbits 32=f32, 64=f64) ---------------------
    if (base == OP_FADD || base == OP_FSUB || base == OP_FMUL || base == OP_FDIV ||
        base == OP_FNEG) {
      Type *fTy = (wbits == 32) ? Type::getFloatTy(Ctx) : Type::getDoubleTy(Ctx);
      auto toF = [&](Value *lane) {
        return B.CreateBitCast(
            wbits == 32 ? (Value *)B.CreateTrunc(lane, Type::getInt32Ty(Ctx)) : lane, fTy);
      };
      Value *fa = toF(loadReg(ra)), *r;
      if (base == OP_FNEG)
        r = B.CreateFNeg(fa);
      else {
        Value *fb = toF(loadReg(rb));
        r = base == OP_FADD ? B.CreateFAdd(fa, fb)
          : base == OP_FSUB ? B.CreateFSub(fa, fb)
          : base == OP_FMUL ? B.CreateFMul(fa, fb)
                            : B.CreateFDiv(fa, fb);
      }
      Value *bits = B.CreateBitCast(r, IntegerType::get(Ctx, wbits));
      storeReg(dst, wbits == 32 ? B.CreateZExt(bits, i64) : bits);
      finish(pc4);
      continue;
    }
    if (base == OP_FEQ || base == OP_FLT || base == OP_FLE || base == OP_FGT ||
        base == OP_FGE || base == OP_FNE) {
      Type *fTy = (wbits == 32) ? Type::getFloatTy(Ctx) : Type::getDoubleTy(Ctx);
      auto toF = [&](Value *lane) {
        return B.CreateBitCast(
            wbits == 32 ? (Value *)B.CreateTrunc(lane, Type::getInt32Ty(Ctx)) : lane, fTy);
      };
      CmpInst::Predicate p = base == OP_FEQ ? CmpInst::FCMP_OEQ
                           : base == OP_FLT ? CmpInst::FCMP_OLT
                           : base == OP_FLE ? CmpInst::FCMP_OLE
                           : base == OP_FGT ? CmpInst::FCMP_OGT
                           : base == OP_FGE ? CmpInst::FCMP_OGE
                                            : CmpInst::FCMP_ONE;
      storeReg(dst, B.CreateZExt(B.CreateFCmp(p, toF(loadReg(ra)), toF(loadReg(rb))), i64));
      finish(pc4);
      continue;
    }
    if (base == OP_FPEXT) {                 // f32 lane -> f64 lane
      Value *f = B.CreateBitCast(B.CreateTrunc(loadReg(ra), Type::getInt32Ty(Ctx)),
                                 Type::getFloatTy(Ctx));
      storeReg(dst, B.CreateBitCast(B.CreateFPExt(f, Type::getDoubleTy(Ctx)), i64));
      finish(pc4);
      continue;
    }
    if (base == OP_FPTRUNC) {               // f64 lane -> f32 lane
      Value *dv = B.CreateFPTrunc(B.CreateBitCast(loadReg(ra), Type::getDoubleTy(Ctx)),
                                  Type::getFloatTy(Ctx));
      storeReg(dst, B.CreateZExt(B.CreateBitCast(dv, Type::getInt32Ty(Ctx)), i64));
      finish(pc4);
      continue;
    }
    if (base == OP_SITOFP) {                // wc: bit1 srcInt(0=i32,1=i64), bit0 dstFloat(0=f32,1=f64)
      unsigned wc = (ob >> 6) & 3;
      bool srcI64 = wc & 2, dstF64 = wc & 1;
      Value *iv = srcI64 ? loadReg(ra)
                         : (Value *)B.CreateTrunc(loadReg(ra), Type::getInt32Ty(Ctx));
      Value *fv = B.CreateSIToFP(iv, dstF64 ? Type::getDoubleTy(Ctx) : Type::getFloatTy(Ctx));
      Value *bits = B.CreateBitCast(fv, IntegerType::get(Ctx, dstF64 ? 64 : 32));
      storeReg(dst, dstF64 ? bits : B.CreateZExt(bits, i64));
      finish(pc4);
      continue;
    }
    if (base == OP_FPTOSI) {                // wc: bit1 dstInt(0=i32,1=i64), bit0 srcFloat(0=f32,1=f64)
      unsigned wc = (ob >> 6) & 3;
      bool dstI64 = wc & 2, srcF64 = wc & 1;
      Value *fv = B.CreateBitCast(
          srcF64 ? loadReg(ra) : (Value *)B.CreateTrunc(loadReg(ra), Type::getInt32Ty(Ctx)),
          srcF64 ? Type::getDoubleTy(Ctx) : Type::getFloatTy(Ctx));
      Value *iv = B.CreateFPToSI(fv, IntegerType::get(Ctx, dstI64 ? 64 : 32));
      storeReg(dst, dstI64 ? iv : B.CreateZExt(iv, i64));
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
  return true;
}

// Make a just-built layer-0 interpreter eligible for a second virtualization pass. (Defined below.)
static void prepareForRevirt(Function &F);

PreservedAnalyses VirtPass::run(Function &F, FunctionAnalysisManager &) {
  if (!rustcloak::flagOn("RUSTCLOAK_VM"))
    return PreservedAnalyses::all();
  if (!selectedForVirt(F))                 // selective/partial scoping (see selectedForVirt)
    return PreservedAnalyses::all();
  if (getenv("RUSTCLOAK_VM_INLINE"))
    inlineTinyCallees(F);                  // fold tiny leaf callees in before virtualizing
  if (!virtualizeOnce(F, 0))
    return PreservedAnalyses::all();
  // Nested virtualization (RUSTCLOAK_VM_NEST): re-virtualize the layer-0 interpreter so its own
  // dispatch loop becomes bytecode for a second, differently-encoded VM -- the multi-layer model of
  // VMProtect/Themida. prepareForRevirt makes the interpreter re-eligible (lower the dispatch switch
  // to a branch tree, de-volatilize the bytecode loads, turn the `unreachable` into a return). The
  // second pass is best-effort: if the interpreter still isn't eligible (e.g. it has an indirect
  // callee-table call), virtualizeOnce leaves it as the correct single layer.
  if (getenv("RUSTCLOAK_VM_NEST")) {
    prepareForRevirt(F);
    virtualizeOnce(F, 1);
  }
  return PreservedAnalyses::none();
}

// Lower a switch into an equivalent icmp/branch chain (the VM accepts only branch/return
// terminators). Assumes the case successors have no PHIs -- true for the interpreter's dispatch,
// whose handlers take no PHI operands (the loop's pc PHI is fed by the handlers, not the switch).
static void lowerSwitch(SwitchInst *sw) {
  BasicBlock *BB = sw->getParent();
  Function *F = BB->getParent();
  LLVMContext &C = F->getContext();
  Value *cond = sw->getCondition();
  BasicBlock *defd = sw->getDefaultDest();
  std::vector<std::pair<ConstantInt *, BasicBlock *>> cases;
  for (auto cs : sw->cases())
    cases.push_back({cs.getCaseValue(), cs.getCaseSuccessor()});
  sw->eraseFromParent();                       // BB loses its terminator; rebuilt below
  IRBuilder<> B(BB);
  BasicBlock *cur = BB;
  for (auto &kv : cases) {
    B.SetInsertPoint(cur);
    Value *e = B.CreateICmpEQ(cond, kv.first);
    BasicBlock *next = BasicBlock::Create(C, "", F);
    B.CreateCondBr(e, kv.second, next);
    cur = next;
  }
  B.SetInsertPoint(cur);
  B.CreateBr(defd);
}

// Make a just-built layer-0 interpreter eligible for a second virtualization pass: drop the
// volatile markers (nothing runs after OptimizerLast to re-fold them, and they become layer-1
// bytecode anyway), turn the unreachable default into a return, and lower the dispatch switch to a
// branch chain. A function whose interpreter still has an indirect callee-table call stays
// ineligible and is left as the correct single layer.
static void prepareForRevirt(Function &F) {
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {
      if (auto *l = dyn_cast<LoadInst>(&I))
        l->setVolatile(false);
      else if (auto *s = dyn_cast<StoreInst>(&I))
        s->setVolatile(false);
    }
  Type *retTy = F.getReturnType();
  for (BasicBlock &BB : F)
    if (isa<UnreachableInst>(BB.getTerminator())) {
      Instruction *term = BB.getTerminator();
      IRBuilder<> B(term);
      if (retTy->isVoidTy())
        B.CreateRetVoid();
      else
        B.CreateRet(UndefValue::get(retTy));
      term->eraseFromParent();
    }
  std::vector<SwitchInst *> sws;
  for (BasicBlock &BB : F)
    if (auto *sw = dyn_cast<SwitchInst>(BB.getTerminator()))
      sws.push_back(sw);
  for (SwitchInst *sw : sws)
    lowerSwitch(sw);
}

PreservedAnalyses PartialOutlinePass::run(Function &F, FunctionAnalysisManager &) {
  if (!getenv("RUSTCLOAK_VM") || !getenv("RUSTCLOAK_VM_PARTIAL") || F.isDeclaration())
    return PreservedAnalyses::all();
  if (F.hasFnAttribute("rc-outlined") || eligible(F))
    return PreservedAnalyses::all();          // already outlined, or wholly handled by the virt pass
  return outlineEligibleRegion(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
