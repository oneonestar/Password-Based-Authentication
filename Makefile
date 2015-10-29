BUILD_DIR := build

all: build/authenticate_user build/create_user

build/authenticate_user: src/authenticate_user.cpp | $(BUILD_DIR)
	g++ src/authenticate_user.cpp src/base64.c lib/libscrypt.a -O3 -o build/authenticate_user -std=gnu++11 -lcrypto -Llib -Ilib

build/create_user: src/create_user.cpp | $(BUILD_DIR)
	g++ src/create_user.cpp src/base64.c lib/libscrypt.a -O3 -o build/create_user -std=gnu++11 -lcrypto -Llib -Ilib

$(BUILD_DIR):
	mkdir -p build

clean:
	rm -f build/create_user build/authenticate_user
