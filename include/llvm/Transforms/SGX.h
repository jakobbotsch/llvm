#ifndef LLVM_SGX_H
#define LLVM_SGX_H

namespace llvm {

class Pass;
class PassManagerBuilder;

/// Duplicate SGX functions creating enter-stubs
Pass* createSGXStubifyPass();

void addSGXPassesToExtensionPoints(PassManagerBuilder &Builder);

#define SGX_SECURE_ATTR "sgx.secure"

}

#endif