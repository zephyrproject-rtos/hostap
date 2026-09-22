ALL=afcd

include ../src/build.rules

CFLAGS += -I../src/utils
CFLAGS += -I../src

OBJS=afcd.o
OBJS += ../src/utils/common.o
OBJS += ../src/utils/wpa_debug.o
OBJS += ../src/utils/wpabuf.o

ifndef CONFIG_OS
ifdef CONFIG_NATIVE_WINDOWS
CONFIG_OS=win32
else
CONFIG_OS=unix
endif
endif
OBJS += ../src/utils/os_$(CONFIG_OS).o

LIBS += -lcurl

_OBJS_VAR := OBJS
include ../src/objs.mk
afcd: $(OBJS)
	$(Q)$(LDO) $(LDFLAGS) -o afcd $(OBJS) $(LIBS)
	@$(E) "  LD " $@

clean: common-clean
	rm -f core *~
