//===- RustCloak.h - shared declarations for the RustCloak obfuscator -----===//
//
// RustCloak is an LLVM new-pass-manager plugin that hardens a program against
// reverse engineering at the LLVM intermediate-representation level. It bundles
// four transforms, each in its own source file:
//
//   flatten  (Flatten.cpp)  control-flow flattening  -- hide the block order
//   strenc   (StrEnc.cpp)   string-literal encryption -- no plaintext in the file
//   subst    (Subst.cpp)    instruction substitution  -- rewrite arithmetic/logic
//   bogus    (Bogus.cpp)    bogus control flow + opaque predicates -- fake branches
//   virt     (Virt.cpp)     code virtualization       -- bytecode + interpreter (RUSTCLOAK_VM=1)
//
// Plugin.cpp registers them: explicitly by name (`-passes=...`) and automatically
// at the end of a default -O pipeline (`clang -O2 -fpass-plugin=...`) so the
// optimizer cannot undo them.
//
//===----------------------------------------------------------------------===//
#ifndef RUSTCLOAK_H
#define RUSTCLOAK_H

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <random>
#include <string>

namespace rustcloak {

// A build flag is "on" if its own environment variable is set, OR RUSTCLOAK_HARDEN selects the
// strong preset that includes it. HARDEN is a one-switch way to turn on the recommended hardening
// (bytecode integrity, encrypted jump-table dispatch, two-way opaque predicates, runtime-derived
// string keys, and depth-2 MBA) without naming each knob -- it does NOT include the ~100x-slower
// nested VM or the scope-narrowing selective modes, which are deliberate per-build choices.
inline bool hardenPreset() {
  static bool h = std::getenv("RUSTCLOAK_HARDEN") != nullptr;
  return h;
}
inline bool flagOn(const char *name) {
  if (std::getenv(name))
    return true;
  if (!hardenPreset())
    return false;
  static const char *const preset[] = {
      "RUSTCLOAK_VM", "RUSTCLOAK_VM_INTEGRITY", "RUSTCLOAK_VM_JMP",
      "RUSTCLOAK_BOGUS_TWOWAY", "RUSTCLOAK_STRENC_SELFKEY"};
  for (const char *p : preset)
    if (std::string(name) == p)
      return true;
  return false;
}

// One base seed per process (per build invocation). The seed comes from the environment variable
// RUSTCLOAK_SEED (any strtoull-parsable value, e.g. 1 or 0x1234); unset -> a fresh random seed per
// build, so every build differs. An env var is used rather than an LLVM `cl::opt` because command-
// line options drag in `llvm::cl::` symbols that a host LLVM (notably the one rustc bundles for
// -Zllvm-plugins) need not export, which stops the plugin loading; an env var is portable.
inline uint64_t baseSeed() {
  static uint64_t s = []() -> uint64_t {
    if (const char *e = std::getenv("RUSTCLOAK_SEED")) {
      char *end = nullptr;
      unsigned long long v = std::strtoull(e, &end, 0);
      if (end != e)
        return (uint64_t)v;
    }
    return (((uint64_t)std::random_device{}() << 32) ^ (uint64_t)std::random_device{}());
  }();
  return s;
}

// A generator derived from the build seed and a tag, so different functions/strings
// get independent streams that are still reproducible for a fixed RUSTCLOAK_SEED.
inline std::mt19937_64 rng(llvm::StringRef tag) {
  uint64_t h = std::hash<std::string>{}(tag.str()) * 0x9e3779b97f4a7c15ull;
  return std::mt19937_64(baseSeed() ^ h);
}

// A seeded, innocuous-looking identifier for an injected global/function. The obfuscator must
// NOT name its own artifacts (`rustcloak.decrypt`, `cloak.state`, ...): those names are a trivial
// grep/YARA signature that identifies the tool and locates the decryptor and dispatcher in any
// non-stripped build. Names are derived from the build seed + `tag`, so a given tag maps to one
// stable name within a build (globals reused by tag still resolve) and differs across builds.
// Local values and blocks get no name at all (LLVM auto-numbers them) -- see the passes.
inline std::string anon(llvm::StringRef tag) {
  auto g = rng(("name:" + tag).str());
  static const char lead[] = "abcdefghijklmnopqrstuvwxyz";
  static const char body[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  std::string s(1, lead[g() % 26]);
  for (int i = 0; i < 9; i++)
    s += body[g() % 36];
  return s;
}

} // namespace rustcloak

// Each transform as a new-PM pass. run() is defined in the matching .cpp.
struct FlattenPass : llvm::PassInfoMixin<FlattenPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
  static bool isRequired() { return true; }
};
struct StrEncPass : llvm::PassInfoMixin<StrEncPass> {
  llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
  static bool isRequired() { return true; }
};
struct SubstPass : llvm::PassInfoMixin<SubstPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
  static bool isRequired() { return true; }
};
struct BogusPass : llvm::PassInfoMixin<BogusPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
  static bool isRequired() { return true; }
};
struct VirtPass : llvm::PassInfoMixin<VirtPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
  static bool isRequired() { return true; }
};
struct ConstEncPass : llvm::PassInfoMixin<ConstEncPass> {
  llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &);
  static bool isRequired() { return true; }
};

#endif // RUSTCLOAK_H
