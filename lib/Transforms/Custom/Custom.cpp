#include "llvm/IR/LegacyPassManager.h"

using namespace llvm;

void llvm::initializeCustom(PassRegistry &Registry) {
  initializeSGXPassPass(Registry);
}

void LLVMInitializeCustom(LLVMPassRegistryRef R) {
  initializeCustom(*unwrap(R));
}