# LLVM with SGX support
This is a custom fork of LLVM that adds SGX support to the tooling.

## Building
LLVM-SGX has been built and tested on Ubuntu 16. First clone LLVM-SGX and Clang-SGX:
```bash
mkdir llvm-sgx && cd llvm-sgx
mkdir llvm && cd llvm
git clone https://github.com/jakobbotsch/llvm-sgx.git llvm
git clone https://github.com/jakobbotsch/clang-sgx.git llvm/tools/clang
```

Next, build it. LLVM/Clang builds the easiest and fastest with cmake using the `ninja` build system, so install those:
```
sudo apt-get install cmake ninja-build
```
And build + install (this will take a while):
```
mkdir install
mkdir build && cd build
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=$(realpath ../install) -DCMAKE_BUILD_TYPE=Release ../llvm
ninja
ninja install
```

Now you have the LLVM-SGX binaries in the ../install directory. Checkout and build OpenSGX (instructions adapted from OpenSGX project):

```bash
cd ../..
git clone https://github.com/jakobbotsch/opensgx.git
cd opensgx
sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libaio-dev libssl-dev
sudo apt-get install libelf-dev
cd qemu
./configure-arch
make -j $(nproc)
cd ..
make -C libsgx
# Note: libllvm-opensgx requires Clang to build, so set up path here (only needed if Clang is not installed)
export PATH=$(realpath ../llvm/install/bin):$PATH
make -C user
```

And finally LLVM-SGX-post:

```bash
cd ..
git clone https://github.com/jakobbotsch/llvm-sgx-post.git
cd llvm-sgx-post
g++ -std=c++17 -O3 main.cpp -lelf -o llvm-sgx-post
```

Now we're ready to compile and run LLVM-SGX programs.

```
cd ..
mkdir test && cd test
cp ../opensgx/user/libllvm-opensgx.a .
cp -R ../opensgx/user/conf conf/
echo '#include <stdio.h>

static secure int AnswerToLife()
{
    return 42;
}

int main()
{
    printf("The answer to life, the universe and everything is: %d\n", AnswerToLife());
}' >> test.c

../llvm/install/bin/clang -fPIC -o test test.c libllvm-opensgx.a
../llvm-sgx-post/llvm-sgx-post test
../opensgx/qemu/x86_64-linux-user/qemu-x86_64 test
```

The example should run successfully.

## Code/differences
LLVM-SGX: [See here](https://github.com/llvm-mirror/llvm/compare/master...jakobbotsch:master)  
Clang-SGX: [See here](https://github.com/llvm-mirror/clang/compare/master...jakobbotsch:master)  
OpenSGX (including libllvm-opensgx): [See here](https://github.com/sslab-gatech/opensgx/compare/master...jakobbotsch:master)
LLVM-SGX-post: [See here](https://github.com/jakobbotsch/llvm-sgx-post/blob/master/main.cpp)