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
    //    and is in regular '.text'. It packs args/return value and uses EENTER
    //    to get into the secure adapter.
    // 2. A secure adapter stub, which is placed in 'sgxtext'. It unpacks args
    //    and the return value, calls the actual implementation and leaves with EEXIT.
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

  bool ReturnsVoid = F.getReturnType() == VoidTy;
  // Create a type containing the return value and all args.
  // Since secure functions only support 1 argument we will
  // use this to pass arbitrary arguments.
  SmallVector<Type *, 8> FrameTypes;
  if (!ReturnsVoid)
    FrameTypes.push_back(F.getReturnType());
  for (const auto &Arg : F.args())
    FrameTypes.push_back(Arg.getType());

  StructType *FrameTy = StructType::get(*C, FrameTypes);
  Type *FramePtrTy = PointerType::getUnqual(FrameTy);

  // Create insecure adapter:
  Function *InsecureAdapter =
    Function::Create(F.getFunctionType(), Function::PrivateLinkage,
                     Twine("__llvmsgx_insadapt_") + F.getName());
  FunctionType *SecureAdapterFTy = FunctionType::get(VoidTy, {FramePtrTy}, false);
  Function *SecureAdapter =
    Function::Create(SecureAdapterFTy, Function::PrivateLinkage,
                     Twine("__llvmsgx_secadapt_") + F.getName());

  F.getParent()->getFunctionList().insert(F.getIterator(), SecureAdapter);
  F.getParent()->getFunctionList().insert(F.getIterator(), InsecureAdapter);
  InsecureAdapter->copyAttributesFrom(&F);
  InsecureAdapter->removeFnAttr(SGX_SECURE_ATTR);

  // Add the following code.
  // secure TRet Func(T1 arg1, T2 arg2, ...) {
  //   FrameTy f;
  //   f.arg1 = arg1;
  //   f.arg2 = arg2;
  //   ...
  //   if (!__llvmsgx_enclave_tcs)
  //     __llvmsgx_enclave_init(&SecureAdapter);
  //   EENTER(__llvmsgx_enclave_tcs, exception_handler, &f);
  //   return f.ret;
  // }

  IRBuilder<> IRB(BasicBlock::Create(*C, "", InsecureAdapter));
  AllocaInst *FrameAlloc = IRB.CreateAlloca(FrameTy);
  uint32_t InsertIndex = ReturnsVoid ? 0 : 1;
  for (auto &Arg : InsecureAdapter->args()) {
    Value *StoredArgAddr =
      IRB.CreateGEP(FrameAlloc, {IRB.getInt32(0), IRB.getInt32(InsertIndex)});
    IRB.CreateStore(&Arg, StoredArgAddr);
    InsertIndex++;
  }

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
    FunctionType::get(VoidTy, {FramePtrTy, Int8PtrTy, Int8PtrTy, Int64Ty}, false);
  InlineAsm *EnterIA = InlineAsm::get(EnterFTy, "enclu", EnterConstraints,
                                      /*hasSideEffect*/true,
                                      /*isAlignStack*/false,
                                      InlineAsm::AD_Intel);

  LoadInst *TailLoad = IRB.CreateLoad(EncTcsGlobal);

  Constant *ConstEEnter = IRB.getInt64(ENCLU_EENTER);
  CallInst *EnterCall =
    IRB.CreateCall(EnterIA, {FrameAlloc, TailLoad, EncEH, ConstEEnter});
  EnterCall->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);

  if (ReturnsVoid)
    IRB.CreateRetVoid();
  else {
    Value *RetValAddr =
      IRB.CreateGEP(FrameAlloc, {IRB.getInt32(0), IRB.getInt32(0)});

    Value *RetVal = IRB.CreateLoad(RetValAddr);
    IRB.CreateRet(RetVal);
  }

  Instruction *Then = SplitBlockAndInsertIfThen(TcsIsNull, TailLoad, false);

  IRB.SetInsertPoint(Then);
  IRB.CreateCall(EncInit, {IRB.CreateBitCast(SecureAdapter, Int8PtrTy)});

  // Create secure adapter. Add this code:
  // void SecureAdapter(FrameTy *f) {
  //   f->ret = SecureFunc(f->arg1, f->arg2, ...);
  //   EEXIT();
  // }
  SecureAdapter->setSection(SGX_SECURE_SECTION);
  IRB.SetInsertPoint(BasicBlock::Create(*C, "", SecureAdapter));

  SmallVector<Value *, 8> SecureToImplArgs;
  for (unsigned i = 0; i < F.getFunctionType()->getNumParams(); i++) {
    unsigned LoadIndex = ReturnsVoid ? i : (1 + i);
    Value *LoadedArgAddr =
      IRB.CreateGEP(&*SecureAdapter->arg_begin(),
                    {IRB.getInt32(0), IRB.getInt32(LoadIndex)});
    Value *LoadedArg = IRB.CreateLoad(LoadedArgAddr);
    SecureToImplArgs.push_back(LoadedArg);
  }

  CallInst *ImplCall = IRB.CreateCall(&F, SecureToImplArgs);
  if (!ReturnsVoid) {
    Value *RetValAddr =
      IRB.CreateGEP(&*SecureAdapter->arg_begin(),
                    {IRB.getInt32(0), IRB.getInt32(0)});
    IRB.CreateStore(ImplCall, RetValAddr);
  }

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

