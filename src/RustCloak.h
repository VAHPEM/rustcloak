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
//
// Plugin.cpp registers them: explicitly by name (`-passes=...`) and automatically
// at the end of a default -O pipeline (`clang -O2 -fpass-plugin=...`) so the
// optimizer cannot undo them.
//
//===----------------------------------------------------------------------===//
#ifndef RUSTCLOAK_H
#define RUSTCLOAK_H

#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"

#include <cstdint>
#include <functional>
#include <random>
#include <string>

namespace rustcloak {

// Build seed. 0 (default) -> a fresh random seed per build, so every build differs;
// a non-zero value gives reproducible builds. Defined in Plugin.cpp.
extern llvm::cl::opt<unsigned> Seed;

// One base seed per process (per build invocation).
inline uint64_t baseSeed() {
  static uint64_t s = Seed ? (uint64_t)Seed
                           : (((uint64_t)std::random_device{}() << 32) ^
                              (uint64_t)std::random_device{}());
  return s;
}

// A generator derived from the build seed and a tag, so different functions/strings
// get independent streams that are still reproducible for a fixed --rustcloak-seed.
inline std::mt19937_64 rng(llvm::StringRef tag) {
  uint64_t h = std::hash<std::string>{}(tag.str()) * 0x9e3779b97f4a7c15ull;
  return std::mt19937_64(baseSeed() ^ h);
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

#endif // RUSTCLOAK_H
