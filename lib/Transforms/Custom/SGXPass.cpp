#define DEBUG_TYPE "sgxpass"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Custom.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

namespace {
  struct SGXPass : public FunctionPass {
    static char ID;
    SGXPass() : FunctionPass(ID) {
      initializeSGXPassPass(*PassRegistry::getPassRegistry());
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

char SGXPass::ID = 0;
INITIALIZE_PASS(SGXPass, "sgx", "Enable placing functions in secure enclaves",
                false, false)

FunctionPass *llvm::createSGXPass() {
  return new SGXPass();
}