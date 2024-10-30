/*******************************************************************************
*   (c) 2018, 2019 Zondax GmbH
*   (c) 2016 Ledger
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

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>

#include "app_main.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "common.h"
#include "addr.h"
#include "ux.h"
#include "actions.h"
#include "coin.h"
#include "view.h"
#include "common/tx.h"
#include "crypto.h"
#include "zxmacros.h"
#include "apdu_codes.h"
#include "bech32.h"
#include "app_mode.h"

uint16_t action_addrResponseLen;

__Z_INLINE uint8_t extractHRP(uint32_t rx, uint32_t offset) {
    if (rx < offset + 1) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    MEMZERO(bech32_hrp, MAX_BECH32_HRP_LEN);

    bech32_hrp_len = G_io_apdu_buffer[offset];

    if (bech32_hrp_len == 0 || bech32_hrp_len > MAX_BECH32_HRP_LEN) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    memcpy(bech32_hrp, G_io_apdu_buffer + offset + 1, bech32_hrp_len);
    bech32_hrp[bech32_hrp_len] = 0;     // zero terminate

    return bech32_hrp_len;
}

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    bool mutable_nodes[HDPATH_LEN_DEFAULT] = {false, false, true, false, true};
    uint32_t expected[HDPATH_LEN_DEFAULT] = {
        HDPATH_0_DEFAULT,  // Purpose
        HDPATH_1_DEFAULT,  // Coin type (chain ID)
        HDPATH_2_DEFAULT,  // Account - MUTABLE
        HDPATH_3_DEFAULT,  // Change (no change addresses for now)
        HDPATH_4_DEFAULT,  // Address index - MUTABLE
    };
   
    // Check for invalid values
    for (uint8_t i = 0; i < HDPATH_LEN_DEFAULT; i++) {
        if (!mutable_nodes[i]) {
            if (hdPath[i] != expected[i]) {
                THROW(APDU_CODE_DATA_INVALID);
            }
        }
    }

    // Limit values unless the app is running in expert mode
    if (!app_mode_expert()) {
        for(int i=2; i < HDPATH_LEN_DEFAULT; i++) {
            // hardened or unhardened values should be below 20
            if ( (hdPath[i] & 0x7FFFFFFF) > 100) THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
        }
    }
}

bool process_chunk(uint32_t rx, bool getBip32) {
    int packageIndex = G_io_apdu_buffer[OFFSET_PCK_INDEX];
    int packageCount = G_io_apdu_buffer[OFFSET_PCK_COUNT];

    uint16_t offset = OFFSET_DATA;
    if (rx < offset) {
        THROW(APDU_CODE_DATA_INVALID);
    }


    if (packageIndex == 1) {
        tx_initialize();
        tx_reset();
        if (getBip32) {
            extractHDPath(rx, offset + 1);
            // must be the last bip32 the user "saw" for signing to work.
            if (memcmp(hdPath, viewed_bip32_path, HDPATH_LEN_DEFAULT) != 0) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            return packageIndex == packageCount;
        }
    }

    if (tx_append(&(G_io_apdu_buffer[offset]), rx - offset) != rx - offset) {
        THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
    }

    return packageIndex == packageCount;
}

void tx_accept_sign() {
    int result = 0;
    size_t length = (size_t) IO_APDU_BUFFER_SIZE;

    result = sign_secp256k1(
            tx_get_buffer(),
            tx_get_buffer_length(),
            G_io_apdu_buffer,
            &length);
    
    uint16_t return_code = APDU_CODE_OK;
    if (result != 1) {
        return_code = APDU_CODE_SIGN_VERIFY_ERROR;
    }
    set_code(G_io_apdu_buffer, length, return_code);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, length + 2);
}

void tx_reject() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    view_idle_show(0,NULL);
}

__Z_INLINE void handleGetVersion(volatile uint32_t *tx) {
#if !defined(TARGET_NANOS)
    unsigned int UX_ALLOWED = (G_ux_params.len != BOLOS_UX_IGNORE && G_ux_params.len != BOLOS_UX_CONTINUE);
#else
    unsigned int UX_ALLOWED = (ux.params.len != BOLOS_UX_IGNORE && ux.params.len != BOLOS_UX_CONTINUE);
#endif

#ifdef TESTING_ENABLED
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;
    G_io_apdu_buffer[4] = !UX_ALLOWED;

    *tx += 5;
    THROW(APDU_CODE_OK);

    return;
}

__Z_INLINE void handleGetUncompressedPubKey(volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA + 1);

    uint8_t raw_pubkey[65];

     if(bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    hdPath,
                                    HDPATH_LEN_DEFAULT,
                                    raw_pubkey,
                                    NULL,
                                    CX_SHA512)  != CX_OK)
    {
        THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
    }

    memmove(G_io_apdu_buffer, raw_pubkey, 65);
    *tx += 65;

    THROW(APDU_CODE_OK);

    return;
}


__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx, bool showAddr) {
    uint8_t HRPlen = extractHRP(rx, OFFSET_DATA);
    
    // Parse arguments
    if (!validate_bnc_hrp()) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    
    extractHDPath(rx, OFFSET_DATA + 1 + HRPlen + 1);

    zxerr_t zxerr = app_fill_address(addr_secp256k1);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    // must be the last bip32 the user "saw" for signing to work.
    memcpy(viewed_bip32_path, hdPath, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    // When showing the address, we just return status ok. The address is not returned (cf. PROTOSPEC.md)
    if (showAddr) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_ok);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    
    *tx = action_addrResponseLen;

    THROW(APDU_CODE_OK);

    return;
}


__Z_INLINE void handleSignSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx){
    if (!process_chunk(rx, true))
        THROW(APDU_CODE_OK);

    const char *error_msg = tx_parse();

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, tx_accept_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < 5) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }
            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handleGetVersion(tx);
                    break;
                }

                // INS_PUBLIC_KEY_SECP256K1 will be deprecated in the near future
                case INS_PUBLIC_KEY_SECP256K1: {
                    handleGetUncompressedPubKey(tx, rx);
                    break;
                }

                case INS_SHOW_ADDR_SECP256K1: {
                    handleGetAddrSecp256K1(flags, tx, rx, true);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    handleGetAddrSecp256K1(flags, tx, rx, false);
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    handleSignSecp256K1(flags, tx, rx);
                    break;
                }

#ifdef TESTING_ENABLED
                case INS_HASH_TEST: {
                    if (process_chunk(rx, false)) {
                        uint8_t message_digest[CX_SHA256_SIZE];

                        cx_hash_sha256(tx_get_buffer(),
                                       tx_get_buffer_length(),
                                       message_digest,
                                       CX_SHA256_SIZE);

                        memmove(G_io_apdu_buffer, message_digest, CX_SHA256_SIZE);
                        *tx += 32;
                    }
                    THROW(APDU_CODE_OK);
                }
                break;
                case INS_PUBLIC_KEY_SECP256K1_TEST: {
                    // Generate key
                    uint8_t raw_pubkey[65];
                    if(bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    hdPath,
                                    HDPATH_LEN_DEFAULT,
                                    raw_pubkey,
                                    NULL,
                                    CX_SHA512)  != CX_OK)
                    {
                        THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
                    }

                    memmove(G_io_apdu_buffer, raw_pubkey, 65);
                    *tx += 65;

                    THROW(APDU_CODE_OK);
                }
                break;
                case INS_SIGN_SECP256K1_TEST: {
                    if (process_chunk(rx, false)) {
                        size_t length = (size_t) IO_APDU_BUFFER_SIZE;

                        // Skip UI and validation
                        sign_secp256k1(tx_get_buffer(),
                                       tx_get_buffer_length(),
                                       G_io_apdu_buffer,
                                       &length);

                        *tx += length;
                    }
                    THROW(APDU_CODE_OK);
                }
                break;
#endif

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}