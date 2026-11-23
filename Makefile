ifndef TARGET_COMPILE
TARGET_COMPILE = aarch64-linux-gnu-
endif
ifndef KP_DIR
KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := kx_mem_rw.o

all: kx_mem_rw.kpm

kx_mem_rw.kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) -fPIC $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm *.o
