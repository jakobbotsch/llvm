#include "SGXInternal.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

void llvm::initializeSGX(PassRegistry &Registry) 
{
  initializeSGXStubifyPass(Registry);
}

static void addSGXOpt0Passes(const PassManagerBuilder &Builder,
                             legacy::PassManagerBase &PM) {
  PM.add(createSGXStubifyPass());
}

static void addSGXOptimizerLastPasses(const PassManagerBuilder &Builder,
                                      legacy::PassManagerBase &PM) {
  PM.add(createSGXStubifyPass());
}

void llvm::addSGXPassesToExtensionPoints(PassManagerBuilder &Builder) {
  Builder.addExtension(PassManagerBuilder::EP_EnabledOnOptLevel0,
                       addSGXOpt0Passes);
  Builder.addExtension(PassManagerBuilder::EP_OptimizerLast,
                       addSGXOptimizerLastPasses);
}
