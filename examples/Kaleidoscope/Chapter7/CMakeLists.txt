set(LLVM_LINK_COMPONENTS
  Analysis
  Core
  ExecutionEngine
  InstCombine
  Object
  RuntimeDyld
  ScalarOpts
  SGX
  Support
  TransformUtils
  native
  )

add_kaleidoscope_chapter(Kaleidoscope-Ch7
  toy.cpp
  )

export_executable_symbols(Kaleidoscope-Ch7)
