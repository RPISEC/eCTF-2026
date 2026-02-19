MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
LNK = $(TICLANG_ARMCOMPILER)/bin/tiarmclang
OBJCOPY = $(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy
BUILDDIR ?= /tmp/build
VPATH = "src"
LINKERFILE = "firmware.ld"

# Perform AES tests
AES_TEST = 0

OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so \
    $(BUILDDIR)/simple_trng.so \
    $(BUILDDIR)/hardware_crypto.so \
    $(BUILDDIR)/timer.so \
    $(BUILDDIR)/wallet.so

ifeq ($(AES_TEST), 1)
OBJECTS +=$(BUILDDIR)/aes_test.so
CFLAGS += -DAES_TEST=1
endif


# change C flags
CFLAGS += -DNO_WOLFSSL_DIR
CFLAGS += -DWOLFSSL_AES_DIRECT
CFLAGS += -DSINGLE_THREADED
# From https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT
CFLAGS += -DNO_FILESYSTEM
# tells wolfssl that we will handle RNG on the baremetal target
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLF_CRYPTO_CB
CFLAGS += -DWOLFSSL_SMALL_STACK
CFLAGS += -DWOLFCRYPT_ONLY # we only need the wolfcrypt library, not all of wolfssl
CFLAGS += -DHAVE_AESGCM
CFLAGS += -DMAX_CRYPTO_DEVID_CALLBACKS=2  # one for the trng and one for the hardware crypto accelerator

WOLFSSL_INC = wolfssl/wolfcrypt/src
CFLAGS += -I./wolfssl

# needed for wolfcrypt
OBJECTS += $(WOLFSSL_INC)/aes.o $(WOLFSSL_INC)/cryptocb.o
OBJECTS += $(WOLFSSL_INC)/wc_port.o $(WOLFSSL_INC)/pwdbased.o
OBJECTS += $(WOLFSSL_INC)/memory.o $(WOLFSSL_INC)/hash.o
OBJECTS += $(WOLFSSL_INC)/hmac.o $(WOLFSSL_INC)/sha.o
OBJECTS += $(WOLFSSL_INC)/md5.o $(WOLFSSL_INC)/sha256.o

NAME = hsm

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    -I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include \
    -I$(MSPM0_SDK_INSTALL_DIR)/source \
	-I./inc \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_INC)/%.o: $(WOLFSSL_INC)/%.c
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS)  $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).elf > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1


CLANGD_DB = compile_commands.json

clangd-db:
	@echo "Generating $(CLANGD_DB)"
	@echo '[' > $(CLANGD_DB)
	@first=1; \
	for f in src/*.c; do \
		if [ $$first -eq 0 ]; then echo ',' >> $(CLANGD_DB); fi; \
		first=0; \
		echo '  {' >> $(CLANGD_DB); \
		echo '    "directory": "$(PROJECT_ROOT)/firmware",' >> $(CLANGD_DB); \
		echo '    "command": "$(CC) $(CFLAGS) -c '$$f'",' >> $(CLANGD_DB); \
		echo '    "file": "'$$f'"' >> $(CLANGD_DB); \
		echo '  }' >> $(CLANGD_DB); \
	done
	@echo ']' >> $(CLANGD_DB)
