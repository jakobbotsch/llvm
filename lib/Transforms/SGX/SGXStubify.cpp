#define DEBUG_TYPE "sgx-stubify"

#include "llvm/Pass.h"
#include "SGXInternal.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Function.h"

using namespace llvm;

namespace {
  struct SGXStubify : public FunctionPass {
    static char ID;
    SGXStubify() : FunctionPass(ID) {
      initializeSGXStubifyPass(*PassRegistry::getPassRegistry());
    }

    /*
     * Just print the function name 
     */
    bool runOnFunction(Function &F) {
      bool Changed = false;
      errs().write_escaped(F.getName()) << "\n";
      return Changed;
    }
  };
}

char SGXStubify::ID = 0;
INITIALIZE_PASS(
    SGXStubify, "sgx-stubify",
    "Stubify SGX secure functions", false, false)

Pass *llvm::createSGXStubifyPass() { return new SGXStubify(); }

