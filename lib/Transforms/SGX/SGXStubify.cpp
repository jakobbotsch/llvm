#include "SGXInternal.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <tuple>

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
  Constant *EncTcsGlobal;
  Constant *EncInit;
  Constant *EncEH;

  Function *createAdapter(Function& F);
};

bool SGXStubify::runOnModule(Module &M) {
  C = &M.getContext();

  // LLVMSGX runtime externals
  Type *Int8Ty = Type::getInt8Ty(*C);
  Type *VoidTy = Type::getVoidTy(*C);
  Type *Int8PtrTy = Type::getInt8PtrTy(*C);

  EncTcsGlobal =
    M.getOrInsertGlobal("__llvmsgx_enclave_tcs", Int8PtrTy);
  EncInit = M.getOrInsertFunction("__llvmsgx_enclave_init",
                                            VoidTy,
                                            Int8PtrTy);
  // OpenSGX EH support (TODO: remove the need for this)
  EncEH = M.getOrInsertGlobal("exception_handler", Int8Ty);

  SmallVector<Function *, 16> SecureFuncs;
  for (Function &F : M.functions()) {
    if (F.hasFnAttribute(SGX_SECURE_ATTR))
      SecureFuncs.push_back(&F);
  }

  for (Function *F : SecureFuncs) {
    F->setSection(SGX_SECURE_SECTION);

    // If a secure function has insecure callers we need to split the function
    // into 3 different functions:
    // 1. The insecure adapter stub, which can be called from insecure functions
    //    and is in regular '.text'. It uses EENTER to get into the secure adapter.
    // 2. A secure adapter stub, which is placed in 'sgxtext'. It calls the actual
    //    implementation and leaves with EEXIT.
    // 3. The actual function, placed in 'sgxtext'.
    // If there are only secure callers then we can just move it into sgxtext
    // directly.
    SmallVector<Instruction *, 16> InsecureCalls;
    for (Use &U : F->uses()) {
      User *FU = U.getUser();
      if (!isa<CallInst>(FU) && !isa<InvokeInst>(FU))
        continue;

      // Ensure the function is actually called and not used as an arg
      Instruction *Inst = cast<Instruction>(FU);
      ImmutableCallSite CS(Inst);
      if (!CS.isCallee(&U))
        continue;

      // Do not modify secure-to-secure calls at all.
      // Check both 'secure' attribute but also section in case someone
      // wants to add functions manually in the future.
      if (CS.getCaller()->hasFnAttribute(SGX_SECURE_ATTR) ||
          CS.getCaller()->getSection() == SGX_SECURE_SECTION)
        continue;

      InsecureCalls.push_back(Inst);
    }

    if (InsecureCalls.empty())
      continue; // no adapter necessary

    Function *InsecureAdapter = createAdapter(*F);
    for (Instruction *I : InsecureCalls) {
      CallSite CS(I);

      if (CallInst *Call = dyn_cast<CallInst>(I))
        Call->setCalledFunction(InsecureAdapter);
      if (InvokeInst *Invoke = dyn_cast<InvokeInst>(I))
        Invoke->setCalledFunction(InsecureAdapter);
    }
  }

  bool AnyGV = false;
  for (GlobalVariable& GV : M.globals()) {
    if (!GV.hasAttribute(SGX_SECURE_ATTR))
      continue;

    GV.setSection(SGX_SECURE_SECTION);
    AnyGV = true;
  }

  return !SecureFuncs.empty() || AnyGV;
}

// Creates an adapter that when used from an insecure function
// calls the specified secure function.
Function *SGXStubify::createAdapter(Function &F) {
  Type *Int64Ty = Type::getInt64Ty(*C);
  Type *VoidTy = Type::getVoidTy(*C);
  Type *Int8PtrTy = Type::getInt8PtrTy(*C);
  Type *Int32PtrTy = Type::getInt32PtrTy(*C);

  // Create insecure adapter:
  FunctionType *FTy = F.getFunctionType();
  Function *InsecureAdapter =
    Function::Create(FTy, Function::PrivateLinkage,
                     Twine("__llvmsgx_insadapt_") + F.getName());
  Function *SecureAdapter =
    Function::Create(FTy, Function::PrivateLinkage,
                     Twine("__llvmsgx_secadapt_") + F.getName());

  F.getParent()->getFunctionList().insert(F.getIterator(), SecureAdapter);
  F.getParent()->getFunctionList().insert(F.getIterator(), InsecureAdapter);
  InsecureAdapter->copyAttributesFrom(&F);
  InsecureAdapter->removeFnAttr(SGX_SECURE_ATTR);

  // Add the following code:
  // if (!__llvmsgx_enclave_tcs)
  //   __llvmsgx_enclave_init(&SecureAdapter);
  // EENTER(__llvmsgx_enclave_tcs, exception_handler);

  IRBuilder<> IRB(BasicBlock::Create(*C, "", InsecureAdapter));
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
    FunctionType::get(VoidTy, {Int32PtrTy, Int8PtrTy, Int8PtrTy, Int64Ty}, false);
  InlineAsm *EnterIA = InlineAsm::get(EnterFTy, "enclu", EnterConstraints,
                                      /*hasSideEffect*/true,
                                      /*isAlignStack*/false,
                                      InlineAsm::AD_Intel);

  LoadInst *TailLoad = IRB.CreateLoad(EncTcsGlobal);

  Constant *ConstEEnter = IRB.getInt64(ENCLU_EENTER);
  CallInst *EnterCall =
    IRB.CreateCall(EnterIA, {&*InsecureAdapter->arg_begin(), TailLoad, EncEH, ConstEEnter});
  EnterCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);

  IRB.CreateRetVoid();

  Instruction *Then = SplitBlockAndInsertIfThen(TcsIsNull, TailLoad, false);

  IRBuilder<> IRBThen(Then);
  IRBThen.CreateCall(EncInit, {IRB.CreateBitCast(SecureAdapter, Int8PtrTy)});

  // Create secure adapter. It calls the implementation followed by EEXIT.
  SecureAdapter->setSection(SGX_SECURE_SECTION);
  IRB.SetInsertPoint(BasicBlock::Create(*C, "", SecureAdapter));

  IRB.CreateCall(&F, {&*SecureAdapter->arg_begin()});
  FunctionType *ExitFTy = FunctionType::get(VoidTy, {Int64Ty, Int64Ty}, false);
  InlineAsm *ExitIA = InlineAsm::get(ExitFTy, "enclu",
                                     // Does not return, so no clobbers necessary
                                     "{bx},{ax}",
                                     /*hasSideEffect*/true,
                                     /*isAlignStack*/false,
                                     InlineAsm::AD_Intel);
  Constant *Const0 = IRB.getInt64(0);
  Constant *ConstEExit = IRB.getInt64(ENCLU_EEXIT);

  CallInst *ExitCall = IRB.CreateCall(ExitIA, {Const0, ConstEExit});
  ExitCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
  ExitCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoReturn);

  IRB.CreateRetVoid();

  return InsecureAdapter;
}
}

char SGXStubify::ID = 0;
INITIALIZE_PASS(
    SGXStubify, "sgx-stubify",
    "Stubify SGX secure functions", false, false)

Pass *llvm::createSGXStubifyPass() { return new SGXStubify(); }

