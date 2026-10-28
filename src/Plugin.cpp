//===- Plugin.cpp - RustCloak pass-plugin registration ---------------------===//
#include "RustCloak.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include <cstdlib>

using namespace llvm;

// The build seed comes from the RUSTCLOAK_SEED environment variable (see RustCloak.h); no LLVM
// command-line option is registered, so the plugin pulls in no `llvm::cl::` symbols and loads
// cleanly into any host LLVM of the matching major version, rustc's -Zllvm-plugins included.

// Add the per-function transforms in order: virtualize first (so the interpreter it emits is then
// itself substituted, given bogus flow and flattened), then substitute, add bogus flow, flatten.
static void addFunctionTransforms(FunctionPassManager &FPM) {
  FPM.addPass(VirtPass());
  FPM.addPass(ConstEncPass());
  FPM.addPass(SubstPass());
  FPM.addPass(BogusPass());
  FPM.addPass(FlattenPass());
}

llvm::PassPluginLibraryInfo getRustCloakPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "RustCloak", "1.0",
          [](PassBuilder &PB) {
            // Explicit use: `-passes=flatten|subst|bogus` (function) / `-passes=strenc` (module).
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "flatten") { FPM.addPass(FlattenPass()); return true; }
                  if (Name == "subst")   { FPM.addPass(SubstPass());   return true; }
                  if (Name == "bogus")   { FPM.addPass(BogusPass());   return true; }
                  if (Name == "virt")    { FPM.addPass(VirtPass());    return true; }
                  if (Name == "constenc") { FPM.addPass(ConstEncPass()); return true; }
                  return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "strenc") { MPM.addPass(StrEncPass()); return true; }
                  return false;
                });
            // Automatic: loading the plugin into a default -O pipeline
            // (clang -O2 -fpass-plugin=...) obfuscates at the END, so the optimizer's
            // own passes cannot undo it. RUSTCLOAK_OFF=1 disables this.
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  if (getenv("RUSTCLOAK_OFF"))
                    return;
                  MPM.addPass(StrEncPass());
                  FunctionPassManager FPM;
                  addFunctionTransforms(FPM);
                  MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return getRustCloakPluginInfo();
}
