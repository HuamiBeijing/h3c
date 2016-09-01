ARCH ?= amd64

include makefiles/Makefile.$(ARCH)
INCLUDE_PATH := inc
SOURCE_PATH := src
LIBRARY_PATH := lib
LIBRARIES := libhbeaconservice

CFLAGS += -I$(INCLUDE_PATH) -g

ifeq ($(ARCH), mips)
CFLAGS += -DCROSS
endif

SOURCES := $(shell echo $(SOURCE_PATH)/*.c)
HEADERS := $(shell echo $(INCLUDE_PATH)/*.h)
OBJECTS := $(SOURCES:.c=.o)

TARGET := $(LIBRARY_PATH)/$(LIBRARIES).so

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET)

strip:
	$(STRIP) -s $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)
