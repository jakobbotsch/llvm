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

enum ENCLU_LEAF {
  ENCLU_EENTER = 2,
  ENCLU_EEXIT = 4,
};

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
  Type *Int8Ty = Type::getInt8Ty(*C);
  Type *Int32Ty = Type::getInt32Ty(*C);
  Type *Int64Ty = Type::getInt64Ty(*C);

  Type *VoidTy = Type::getVoidTy(*C);

  Type *Int8PtrTy = Type::getInt8PtrTy(*C);
  Type *Int32PtrTy = Type::getInt32PtrTy(*C);

  Constant *EncTcsGlobal =
    M.getOrInsertGlobal("__llvmsgx_enclave_tcs", Int8PtrTy);
  Constant *EncInit = M.getOrInsertFunction("__llvmsgx_enclave_init",
                                            VoidTy,
                                            Int8PtrTy);
  Constant *EncEH = M.getOrInsertGlobal("exception_handler", Int8Ty);

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
    // EENTER(__llvmsgx_enclave_tcs, exception_handler);

    IRBuilder<> IRB(BasicBlock::Create(*C, "", &F));
    Value *TcsIsNull = IRB.CreateICmpEQ(IRB.CreateLoad(EncTcsGlobal),
                                        Constant::getNullValue(Int8PtrTy));

    const char *EnterConstraints =
      // First get inputs:
      // D = rdi <- first arg
      // b = rbx <- TCS
      // c = rcx <- AEP
      // a = rax <- leaf func (EENTER)
      "{di},{bx},{cx},{ax},"
      // Now clobbers. Since this is a call we actually clobber
      // most regs, however here we just take a subset since
      // there is an internal limit on the number of clobbers.
      // Clobbered by returning EEXIT
      "~{bx},"
      // Scratch registers
      "~{ax},~{cx},~{dx},~{si},~{di},"
      "~{r8},~{r9},~{r10},~{r11},"
      "~{flags},~{memory}";

    FunctionType *EnterFTy =
      FunctionType::get(VoidTy, {Int32PtrTy, Int8PtrTy, Int8PtrTy, Int32Ty}, false);
    InlineAsm *EnterIA = InlineAsm::get(EnterFTy, "enclu", EnterConstraints,
                                        /*hasSideEffect*/true,
                                        /*isAlignStack*/false,
                                        InlineAsm::AD_Intel);

    LoadInst *TailLoad = IRB.CreateLoad(EncTcsGlobal);

    Constant *ConstEEnter = ConstantInt::get(Type::getInt32Ty(*C), ENCLU_EENTER);
    CallInst *EnterCall =
      IRB.CreateCall(EnterIA, {&*F.arg_begin(), TailLoad, EncEH, ConstEEnter});
    EnterCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);

    IRB.CreateRetVoid();

    Instruction *Then = SplitBlockAndInsertIfThen(TcsIsNull, TailLoad, false);

    IRBuilder<> IRBThen(Then);
    IRBThen.CreateCall(EncInit, {IRB.CreateBitCast(NF, Int8PtrTy)});

    // Patch sgx_exit in before returns
    for (auto &BB : NF->getBasicBlockList()) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        FunctionType *ExitFTy = FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
        InlineAsm *ExitIA = InlineAsm::get(ExitFTy, "enclu",
                                           // Does not return, so no clobbers necessary
                                           "{bx},{ax}",
                                           /*hasSideEffect*/true,
                                           /*isAlignStack*/false,
                                           InlineAsm::AD_Intel);
        Constant *Const0 = ConstantInt::get(Int64Ty, 0);
        Constant *ConstEExit = ConstantInt::get(Int64Ty, ENCLU_EEXIT);

        CallInst *ExitCall = CallInst::Create(ExitIA, {Const0, ConstEExit}, "", RI);
        ExitCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
        ExitCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);
      }
    }
  }

  for (GlobalVariable& GV : M.globals())
  {
    if (!GV.hasAttribute(SGX_SECURE_ATTR))
      continue;

    GV.setSection("sgxtext");
    Any = true;
  }

  return Any;
}
}

char SGXStubify::ID = 0;
INITIALIZE_PASS(
    SGXStubify, "sgx-stubify",
    "Stubify SGX secure functions", false, false)

Pass *llvm::createSGXStubifyPass() { return new SGXStubify(); }

