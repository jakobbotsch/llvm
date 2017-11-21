# LLVM with SGX support
This is a custom fork of LLVM that adds SGX support to the tooling.
<more to come>

## Building
For all platforms, download and install CMake. Then set up the environment, making
sure that the repos are cloned into llvm and clang folders (instead of llvm-sgx and clang-sgx):
```
cd <root where llvm, build, and install folders will live>
git clone git@github.com:jakobbotsch/llvm-sgx.git llvm
git clone git@github.com:jakobbotsch/clang-sgx.git llvm/tools/clang
mkdir build
mkdir install
cd build
```
Now use cmake to generate build files depending on your build environment:

### Windows
Assuming C:\llvm\install was the folder created above, run:
```
cmake -G "Visual Studio 15 2017 Win64" -Thost=x64 -DCMAKE_INSTALL_PREFIX=C:/llvm/install ../llvm
```

Now open C:\llvm\build\LLVM.sln in VS 2017 and build the "install" project.

### Other platforms
TODO. However everything should work the same by using CMake.

## Differences
LLVM: [See here](https://github.com/llvm-mirror/llvm/compare/master...jakobbotsch:master)  
Clang: [See here](https://github.com/llvm-mirror/clang/compare/master...jakobbotsch:master)