#include "SGXInternal.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

void llvm::initializeSGX(PassRegistry &Registry) 
{
  initializeSGXStubifyPass(Registry);
}

