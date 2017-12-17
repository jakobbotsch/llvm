#include "llvm/Transforms/SGX.h"

namespace llvm {
	class PassRegistry;

	void initializeSGXStubifyPass(PassRegistry &);
}
