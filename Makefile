.PHONY: all release release-shared-libs debug debug-shared-libs test clean

all: release;

release:
	BUILD_TYPE=Release ./build.sh

release-shared-libs:
	BUILD_TYPE=Release IWNET_BUILD_SHARED_LIBS=1 ./build.sh

debug:
	BUILD_TYPE=Debug ./build.sh 

debug-shared-libs:
	BUILD_TYPE=Debug IWNET_BUILD_SHARED_LIBS=1 ./build.sh 

test:
	BUILD_TYPE=Debug IWNET_RUN_TESTS=1 ./build.sh 

test-release:
	BUILD_TYPE=Release IWNET_RUN_TESTS=1 ./build.sh 

clean:
	rm -rf ./autark-cache
