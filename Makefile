.DEFAULT_GOAL := all
BUILD_DIR=build
BIN_DIR=bin


define win_mkdir
	if not exist "$(abspath $(1))" mkdir "$(abspath $(1))"
endef

define mkdir
	$(if $(filter $(OS), Windows_NT), $(call win_mkdir,$(1)), mkdir -p $(1))
endef

define rm
	$(if $(filter $(OS), Windows_NT), rd /S /Q $(1), rm -rf $(1))
endef

clean:
	$(call rm, $(BUILD_DIR))
	$(call rm, $(BIN_DIR))
	
config: 
	$(if $(filter $(OS), Windows_NT), cmake . -B$(BUILD_DIR) -G "MinGW Makefiles", cmake . -B$(BUILD_DIR))

all:
	cd ./build && make
	echo "\nBuild Completed.\n"

proto:
	cd ./src/proto && \
	protoc --cpp_out=../lib code-audit.proto