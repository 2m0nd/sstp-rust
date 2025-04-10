UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    TARGET_DIR := target-linux
endif
ifeq ($(UNAME_S),Darwin)
    TARGET_DIR := target-macos
endif

build:
	CARGO_TARGET_DIR=$(TARGET_DIR) cargo build --release
