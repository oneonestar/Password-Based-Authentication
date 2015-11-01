BUILD_DIR := build

all: build/authenticate_user build/create_user

build/authenticate_user: src/authenticate_user.cpp | $(BUILD_DIR)
	g++ src/authenticate_user.cpp lib/libscrypt.a -O3 -o build/authenticate_user -std=gnu++11 -lcrypto -Llib -Ilib -Wall

build/create_user: src/create_user.cpp | $(BUILD_DIR)
	g++ src/create_user.cpp lib/libscrypt.a -O3 -o build/create_user -std=gnu++11 -lcrypto -Llib -Ilib

$(BUILD_DIR):
	mkdir -p build

test: all
#create user
	@printf "\033[0;32mTest input: test/test1.input\n"
	@printf "cat test/test1.input\n"
	@printf "\033[0m"
	@cat test/test1.input
	@printf "\n\033[0;32m./build/create_user < test/test1.input\033[0m\n"
	@./build/create_user < test/test1.input
	@printf "\033[0;32mlist.txt has been generated\033[0m\n"
#print list.txt
	@printf "\n\033[0;32mPrint list.txt\033[0m\n"
	@cat list.txt
	@echo
#authenticate user
	@printf "\n\033[0;32m./build/authenticate_user < test/test1.test\033[0m\n"
	@./build/authenticate_user < test/test1.test
	@printf "\n\033[0;32mTesting Finished.\033[0m\n"
	@printf "\033[0;32mShould be 6 failed and 3 succeed.\033[0m\n"

.PHONY: test clean

clean:
	rm -f build/create_user build/authenticate_user list.txt
