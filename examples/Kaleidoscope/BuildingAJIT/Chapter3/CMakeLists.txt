set(LLVM_LINK_COMPONENTS
  Analysis
  Core
  ExecutionEngine
  InstCombine
  Object
  OrcJIT
  RuntimeDyld
  ScalarOpts
  SGX
  Support
  TransformUtils
  native
  )

add_kaleidoscope_chapter(BuildingAJIT-Ch3
  toy.cpp
  )

export_executable_symbols(BuildingAJIT-Ch3)
