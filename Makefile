ifndef TARGET_COMPILE
$(error TARGET_COMPILE not set)
endif
ifndef KP_DIR
KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc

# KernelPatch-এর জন্য প্রয়োজনীয় ফ্ল্যাগ
CFLAGS += -nostdinc
CFLAGS += -fno-pic -fno-PIC -fno-pie -fno-stack-protector
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := kx_mem_rw.o

all: kx_mem_rw.kpm

kx_mem_rw.kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm *.o
