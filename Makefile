#*******************************************************************************
#   Ledger App
#   (c) 2019 Binance
#   (c) 2018 ZondaX GmbH
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

dummy_submodules := $(shell git submodule update --init --recursive)

ifeq ($(TARGET_NAME),TARGET_NANOS)
APP_STACK_SIZE:=880
endif

include $(BOLOS_SDK)/Makefile.defines

# Main app configuration
APPNAME="Binance Chain"
APPVERSION_M=1
APPVERSION_N=1
APPVERSION_P=7

APP_LOAD_PARAMS = --appFlags 0x200 --delete $(COMMON_LOAD_PARAMS) --path "44'/714'"

ifeq ($(TARGET_NAME), TARGET_NANOS)
ICONNAME=nanos_app_binance.gif
else ifeq ($(TARGET_NAME),TARGET_STAX)
ICONNAME=stax_app_binance.gif
else
ICONNAME=nanox_app_binance.gif
endif

############
# Platform

DEFINES   += UNUSED\(x\)=\(void\)x

DEFINES   += APPNAME=\"$(APPNAME)\"

APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES += OS_IO_SEPROXYHAL
DEFINES += HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P)

DEFINES   += HAVE_U2F HAVE_IO_U2F
DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += U2F_PROXY_MAGIC=\"CSM\"
DEFINES   += U2F_MAX_MESSAGE_SIZE=264 #257+5+2

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY
DEFINES   += LEDGER_SPECIFIC

#Feature temporarily disabled
#DEFINES += TESTING_ENABLED
#DEFINES += FEATURE_ED25519

#WEBUSB_URL     = www.ledgerwallet.com
#DEFINES       += HAVE_WEBUSB WEBUSB_URL_SIZE_B=$(shell echo -n $(WEBUSB_URL) | wc -c) WEBUSB_URL=$(shell echo -n $(WEBUSB_URL) | sed -e "s/./\\\'\0\\\',/g")
DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

# Bluetooth
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX))
DEFINES   += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=128
else ifeq ($(TARGET_NAME),TARGET_STAX)
	DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
	DEFINES       += NBGL_QRCODE
else
    DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
    DEFINES       += HAVE_GLO096
    DEFINES       += BAGL_WIDTH=128 BAGL_HEIGHT=64
    DEFINES       += HAVE_BAGL_ELLIPSIS # long label truncation feature
    DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
    DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
    DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
	DEFINES       += HAVE_UX_FLOW
endif

# Both nano S and X benefit from the flow.
ifneq ($(TARGET_NAME),TARGET_STAX)
	DEFINES   += HAVE_BAGL
endif

# Enabling debug PRINTF
DEBUG = 0
ifneq ($(DEBUG),0)

        ifeq ($(TARGET_NAME),TARGET_NANOS)
                DEFINES   += HAVE_PRINTF PRINTF=screen_printf
        else
                DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
        endif
else
        DEFINES   += PRINTF\(...\)=
endif

##############
#  Compiler  #
##############

CC       := $(CLANGPATH)clang
AS       := $(GCCPATH)arm-none-eabi-gcc
LD       := $(GCCPATH)arm-none-eabi-gcc
LDLIBS   += -lm -lgcc -lc

##########################

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += $(CURDIR)/src
APP_SOURCE_PATH += $(CURDIR)/glyphs

ZXLIB_DIR := $(CURDIR)/deps/ledger-zxlib
APP_SOURCE_PATH += $(ZXLIB_DIR)/include
APP_SOURCE_PATH += $(ZXLIB_DIR)/src
APP_SOURCE_PATH += $(ZXLIB_DIR)/app/common
APP_SOURCE_PATH += $(ZXLIB_DIR)/app/ui

APP_SOURCE_PATH += deps/jsmn/src
SDK_SOURCE_PATH += lib_stusb lib_u2f lib_stusb_impl

# INCLUDES_PATH += deps/ledger-zxlib/include

ifeq ($(TARGET_NAME),TARGET_NANOX)
SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

ifneq ($(TARGET_NAME),TARGET_STAX)
SDK_SOURCE_PATH += lib_ux
endif

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX))
SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
endif

# Bluetooth
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX))
DEFINES   += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
endif

all: default

load:
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

package:
	./pkgdemo.sh ${APPNAME} ${APPVERSION} ${ICONNAME}

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile.genericwallet


listvariants:
	@echo VARIANTS COIN binance_chain
