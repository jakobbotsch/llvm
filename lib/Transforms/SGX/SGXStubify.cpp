#include "SGXInternal.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#define DEBUG_TYPE "sgx-stubify"

using namespace llvm;

namespace {

struct SGXStubify : public ModulePass {
  static char ID;
  SGXStubify() : ModulePass(ID) {
    initializeSGXStubifyPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override;

private:
  LLVMContext *C;
};

// Splits all SGX secure functions into two functions:
// 1. A stub under the original name
// 2. An SGX secure function, prefixed with __llvmsgx_secure_.
// The second function is placed in the "sgxtext" section
// under private linkage and contains the actual code.
// first function is converted to jump into the OpenSGX-llvm
// runtime to setup the enclave and perform the actual entry.
bool SGXStubify::runOnModule(Module &M) {
  C = &M.getContext();
  Type *Int8PtrTy = Type::getInt8PtrTy(*C);
  Constant *EncTcsGlobal =
    M.getOrInsertGlobal("__llvmsgx_enclave_tcs", Int8PtrTy);
  Constant *EncInit = M.getOrInsertFunction("__llvmsgx_enclave_init",
                                            Type::getVoidTy(*C),
                                            Int8PtrTy);
  Constant *EncEnter = M.getOrInsertFunction("sgx_enter",
                                             Type::getVoidTy(*C),
                                             Int8PtrTy, Int8PtrTy);
  Constant *EncEH = M.getOrInsertGlobal("exception_handler", Type::getInt8Ty(*C));

  bool Any = false;
  for (Function &F : M.functions()) {
    if (!F.hasFnAttribute(SGX_SECURE_ATTR))
      continue;

    Any = true;

    FunctionType *FTy = F.getFunctionType();
    Function *NF = Function::Create(FTy, Function::PrivateLinkage,
                                    Twine("__llvmsgx_secure_") + F.getName());
    NF->copyAttributesFrom(&F);
    NF->removeFnAttr(SGX_SECURE_ATTR);
    NF->setSection("sgxtext");
    M.getFunctionList().insert(F.getIterator(), NF);

    // Transfer implementation...
    NF->getBasicBlockList().splice(NF->begin(), F.getBasicBlockList());
    // Transfer args
    for (Function::arg_iterator I = F.arg_begin(), E = F.arg_end(),
                                I2 = NF->arg_begin();
         I != E; ++I, ++I2) {
      I->replaceAllUsesWith(&*I2);
      I2->setName(I->getName());
    }

    // Add the following code to the old function:
    // if (!__llvmsgx_enclave_tcs)
    //   __llvmsgx_enclave_init(&NF);
    // sgx_enter(__llvmsgx_enclave_tcs, exception_handler);

    IRBuilder<> IRB(BasicBlock::Create(*C, "", &F));
    Value *TcsIsNull = IRB.CreateICmpEQ(IRB.CreateLoad(EncTcsGlobal),
                                        Constant::getNullValue(Int8PtrTy));

    LoadInst *TailLoad = IRB.CreateLoad(EncTcsGlobal);
    IRB.CreateCall(EncEnter, {TailLoad, EncEH});
    IRB.CreateRetVoid();

    Instruction *Then = SplitBlockAndInsertIfThen(TcsIsNull, TailLoad, false);

    IRBuilder<> IRBThen(Then);
    IRBThen.CreateCall(EncInit, {IRB.CreateBitCast(NF, Int8PtrTy)});

    // Patch sgx_exit in before returns
    for (auto &BB : NF->getBasicBlockList()) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        FunctionType *VoidFTy = FunctionType::get(Type::getVoidTy(*C), false);
        // EEXIT
        const char *Asm =
          "mov eax, 4\n"
          "mov rbx, 0\n"
          "enclu";

        const char *Constraints = "~{ax},~{bx},~{dirflag},~{fpsr},~{flags}";

        InlineAsm *IA = InlineAsm::get(VoidFTy, Asm, Constraints,
                                       /*hasSideEffect*/true,
                                       /*isAlignStack*/false,
                                       InlineAsm::AD_Intel);
        CallInst *CI = CallInst::Create(IA, "", RI);
        CI->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
      }
    }
  }

  return Any;
}
}

char SGXStubify::ID = 0;
INITIALIZE_PASS(
    SGXStubify, "sgx-stubify",
    "Stubify SGX secure functions", false, false)

Pass *llvm::createSGXStubifyPass() { return new SGXStubify(); }

