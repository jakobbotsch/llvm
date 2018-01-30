#ifndef LLVM_SGX_H
#define LLVM_SGX_H

namespace llvm {

class Pass;
class PassManagerBuilder;

Pass* createSGXStubifyPass();

#define SGX_SECURE_ATTR "sgx.secure"

}

#endif