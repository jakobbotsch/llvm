#define DEBUG_TYPE "sgx-stubify"

#include "SGXInternal.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// Promotes all global variables and functions with the
// SGX_SECURE_ATTR attribute to live in the "sgxtext"
// section.
static bool promoteDeclsToSGXSections(Module& M) {
  const char* SGXSection = "sgxtext";

  bool Changed = false;

  for (GlobalVariable& G : M.globals()) {
    if (!G.hasAttribute(SGX_SECURE_ATTR))
      continue;

    errs() << "Promoting " << G.getName() << " to " << SGXSection << "\n";
    G.setSection(SGXSection);
    Changed = true;
  }

  for (Function& F : M.functions()) {
    if (!F.hasFnAttribute(SGX_SECURE_ATTR))
      continue;

    errs() << "Promoting " << F.getName() << " to " << SGXSection << "\n";
    F.setSection(SGXSection);
    Changed = true;
  }

  return Changed;
}

namespace {
  struct SGXStubify : public ModulePass {
    static char ID;
    SGXStubify() : ModulePass(ID) {
      initializeSGXStubifyPass(*PassRegistry::getPassRegistry());
    }

    bool runOnModule(Module &M) override {
      bool Changed = false;
      Changed |= promoteDeclsToSGXSections(M);
      return Changed;
    }
  };
}

char SGXStubify::ID = 0;
INITIALIZE_PASS(
    SGXStubify, "sgx-stubify",
    "Stubify SGX secure functions", false, false)

Pass *llvm::createSGXStubifyPass() { return new SGXStubify(); }

