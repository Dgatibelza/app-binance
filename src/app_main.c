/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 ZondaX GmbH
*   (c) 2019 Binance
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "app_main.h"
#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>
#include "ux.h"
#include "actions.h"
#include "coin.h"
#include "view.h"
#include "view_old.h"
#include "lib/tx.h"
#include "crypto.h"
#include "zxmacros.h"
#include "apdu_codes.h"
#include "bech32.h"

#ifdef TESTING_ENABLED
// Generate using always the same private data
// to allow for reproducible results
const uint8_t privateKeyDataTest[] = {
        0x75, 0x56, 0x0e, 0x4d, 0xde, 0xa0, 0x63, 0x05,
        0xc3, 0x6e, 0x2e, 0xb5, 0xf7, 0x2a, 0xca, 0x71,
        0x2d, 0x13, 0x4c, 0xc2, 0xa0, 0x59, 0xbf, 0xe8,
        0x7e, 0x9b, 0x5d, 0x55, 0xbf, 0x81, 0x3b, 0xd4
};
#endif



sigtype_t current_sigtype;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

uint8_t io_event(uint8_t channel) {
    (void) channel;

    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif  // HAVE_BAGL
            break;
        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&  //
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &      //
                  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
        __attribute__((fallthrough));
        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
            UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
            UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
            break;
#ifdef HAVE_NBGL
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;
#endif  // HAVE_NBGL
        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
                    if (UX_ALLOWED) {
                        UX_REDISPLAY();
                    }
            });
            break;
        default:
            UX_DEFAULT_EVENT();
            break;
    }

    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    return 1;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

            // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                return 0; // nothing received from the master so far (it's a tx
                // transaction)
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                              sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(INVALID_PARAMETER);
    }
    return 0;
}

void app_init() {
    io_seproxyhal_init();

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // TARGET_NANOX

    USB_power(0);
    USB_power(1);
    view_idle_show(0,NULL);

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif // HAVE_BLE

    // set the default bip32 path
    bip32_depth = 5;
    uint32_t new_bip32_path[] = {
         44 | 0x80000000,  // purpose
        714 | 0x80000000,  // coin type (chain ID)
          0 | 0x80000000,  // account
          0,               // change (no change addresses for now)
          0,               // address index
    };
    memcpy(bip32_path, new_bip32_path, sizeof(bip32_path));
}

// void extractHDPath(uint32_t rx, uint32_t offset) {
//     if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
//         THROW(APDU_CODE_WRONG_LENGTH);
//     }

//     MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

//     // Check values
//     if (hdPath[0] != HDPATH_0_DEFAULT ||
//         hdPath[1] != HDPATH_1_DEFAULT ||
//         hdPath[3] != HDPATH_3_DEFAULT) {
//         THROW(APDU_CODE_DATA_INVALID);
//     }

//     // Limit values unless the app is running in expert mode
//     if (!app_mode_expert()) {
//         for(int i=2; i < HDPATH_LEN_DEFAULT; i++) {
//             // hardened or unhardened values should be below 20
//             if ( (hdPath[i] & 0x7FFFFFFF) > 100) THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
//         }
//     }
// }


// extract_bip32 extracts the bip32 path from the apdu buffer
bool extract_bip32(uint8_t *depth, uint32_t path[5], uint32_t rx, uint32_t offset) {
    if (rx < offset + 1) {
        return 0;
    }

    *depth = G_io_apdu_buffer[offset];
    const uint16_t req_offset = 4 * *depth + 1 + offset;

    if (rx < req_offset || *depth != 5) {
        return 0;
    }
    memcpy(path, G_io_apdu_buffer + offset + 1, *depth * 4);
    return 1;
}

// validate_bnc_bip32 checks the given bip32 path against an expected one
bool validate_bnc_bip32(uint8_t depth, uint32_t path[5]) {  // path is 10 bytes for compatibility
    // Only paths in the form 44'/714'/{account}'/0/{index} are supported
    // Mutable nodes: account at 2, index at 4
    bool mutable_nodes[] = {false, false, true, false, true};
    uint32_t expected[] = {
         44 | 0x80000000,  // purpose
        714 | 0x80000000,  // coin type (chain ID)
          0 | 0x80000000,  // MUTABLE - account
          0,               // change (no change addresses for now)
          0,               // MUTABLE - address index
    };
    if (depth != 5) {
        return 0;
    }
    if (sizeof(expected) / 4 != depth) {
        return 0;
    }
    for (uint8_t i = 0; i < depth; i++) {
        if (mutable_nodes[i]) continue;
        if (path[i] != expected[i]) return 0;
    }
    return 1;
}








bool process_chunk(volatile uint32_t *tx, uint32_t rx, bool getBip32) {
    int packageIndex = G_io_apdu_buffer[OFFSET_PCK_INDEX];
    int packageCount = G_io_apdu_buffer[OFFSET_PCK_COUNT];

    uint16_t offset = OFFSET_DATA;
    if (rx < offset) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    if (packageIndex == 1) {
        transaction_initialize();
        transaction_reset();
        if (getBip32) {
            if (!extract_bip32(&bip32_depth, bip32_path, rx, OFFSET_DATA)) {
                THROW(APDU_CODE_DATA_INVALID);
            }
            if (!validate_bnc_bip32(bip32_depth, bip32_path)) {
                THROW(APDU_CODE_DATA_INVALID);
            }
            
            // must be the last bip32 the user "saw" for signing to work.
            if (memcmp(bip32_path, viewed_bip32_path, sizeof(viewed_bip32_path)) != 0) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            return packageIndex == packageCount;
        }
    }

    if (transaction_append(&(G_io_apdu_buffer[offset]), rx - offset) != rx - offset) {
        THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
    }

    return packageIndex == packageCount;
}

//region View Transaction Handlers



//endregion

//region View Address Handlers




//endregion



#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

void app_main() {
    volatile uint32_t rx = 0, tx = 0, flags = 0;

    for (;;) {
        volatile uint16_t sw = 0;

        BEGIN_TRY;
        {
            TRY;
            {
                rx = tx;
                tx = 0;
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                if (rx == 0)
                    THROW(APDU_CODE_EMPTY_BUFFER);

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                handleApdu(&flags, &tx, rx);
            }
            CATCH_OTHER(e);
            {
                switch (e & 0xF000) {
                    case 0x6000:
                    case 0x9000:
                        sw = e;
                        break;
                    default:
                        sw = 0x6800 | (e & 0x7FF);
                        break;
                }
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY;
            {}
        }
        END_TRY;
    }
}

#pragma clang diagnostic pop
