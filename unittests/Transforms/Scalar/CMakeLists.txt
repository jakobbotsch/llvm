set(LLVM_LINK_COMPONENTS
  Analysis
  AsmParser
  Core
  Support
  ScalarOpts
  SGX
  TransformUtils
  )

add_llvm_unittest(ScalarTests
  LoopPassManagerTest.cpp
  )
