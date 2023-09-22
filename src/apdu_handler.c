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
    
    // Check values
    if (hdPath[0] != HDPATH_0_DEFAULT ||
        hdPath[1] != HDPATH_1_DEFAULT ||
        hdPath[2] != HDPATH_2_DEFAULT) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Limit values unless the app is running in expert mode
    if (!app_mode_expert()) {
        for(int i=2; i < HDPATH_LEN_DEFAULT; i++) {
            // hardened or unhardened values should be below 20
            if ( (hdPath[i] & 0x7FFFFFFF) > 100) THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
        }
    }
}

bool process_chunk(volatile uint32_t *tx, uint32_t rx, bool getBip32) {
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
    // Generate keys
    cx_ecfp_public_key_t publicKey;
    cx_ecfp_private_key_t privateKey;
    uint8_t privateKeyData[32];

    unsigned int length = 0;
    int result = 0;
    
    os_perso_derive_node_bip32(
            CX_CURVE_256K1,
            hdPath, HDPATH_LEN_DEFAULT,
            privateKeyData, NULL);

    keys_secp256k1(&publicKey, &privateKey, privateKeyData);
    memset(privateKeyData, 0, 32);

    result = sign_secp256k1(
            tx_get_buffer(),
            tx_get_buffer_length(),
            G_io_apdu_buffer,
            IO_APDU_BUFFER_SIZE,
            &length,
            &privateKey);
      
    if (result == 1) {
        set_code(G_io_apdu_buffer, length, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, length + 2);
    } else {
        set_code(G_io_apdu_buffer, length, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, length + 2);
    }
}

void tx_reject() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    view_idle_show(0,NULL);
}

void get_pubkey(cx_ecfp_public_key_t *publicKey) {
    cx_ecfp_private_key_t privateKey;
    uint8_t privateKeyData[32];

    // Generate keys
    os_perso_derive_node_bip32(
            CX_CURVE_256K1,
            hdPath, HDPATH_LEN_DEFAULT,
            privateKeyData, NULL);
    keys_secp256k1(publicKey, &privateKey, privateKeyData);
    memset(privateKeyData, 0, sizeof(privateKeyData));
    memset(&privateKey, 0, sizeof(privateKey));
}

__Z_INLINE void handleGetVersion(volatile uint32_t *tx, uint32_t rx) {
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX)
    unsigned int UX_ALLOWED = (G_ux_params.len != BOLOS_UX_IGNORE && G_ux_params.len != BOLOS_UX_CONTINUE);
#else
    unsigned int UX_ALLOWED = (ux.params.len != BOLOS_UX_IGNORE && ux.params.len != BOLOS_UX_CONTINUE);
#endif

#ifdef TESTING_ENABLED
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    G_io_apdu_buffer[4] = !UX_ALLOWED;

    *tx += 5;
    THROW(APDU_CODE_OK);

    return;
}

__Z_INLINE void handleGetUncompressedPubKey(volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA + 1);

    cx_ecfp_public_key_t publicKey;
    get_pubkey(&publicKey);

    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
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
    if (!process_chunk(tx, rx, true))
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
            PRINTF("Debug trace inside handleApdu\n");
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < 5) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }
            PRINTF("INS: %d\n", G_io_apdu_buffer[OFFSET_INS]);
            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handleGetVersion(tx, rx);
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
                    if (process_chunk(tx, rx, false)) {
                        uint8_t message_digest[CX_SHA256_SIZE];

                        cx_hash_sha256(transaction_get_buffer(),
                                       transaction_get_buffer_length(),
                                       message_digest,
                                       CX_SHA256_SIZE);

                        os_memmove(G_io_apdu_buffer, message_digest, CX_SHA256_SIZE);
                        *tx += 32;
                    }
                    THROW(APDU_CODE_OK);
                }
                break;

                case INS_PUBLIC_KEY_SECP256K1_TEST: {
                    // Generate key
                    cx_ecfp_public_key_t publicKey;
                    cx_ecfp_private_key_t privateKey;
                    keys_secp256k1(&publicKey, &privateKey, privateKeyDataTest );

                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    *tx += 65;

                    THROW(APDU_CODE_OK);
                }
                break;

                case INS_SIGN_SECP256K1_TEST: {
                    if (process_chunk(tx, rx, false)) {

                        unsigned int length = 0;

                        // Generate keys
                        cx_ecfp_public_key_t publicKey;
                        cx_ecfp_private_key_t privateKey;
                        keys_secp256k1(&publicKey, &privateKey, privateKeyDataTest );

                        // Skip UI and validation
                        sign_secp256k1(
                                transaction_get_buffer(),
                                transaction_get_buffer_length(),
                                G_io_apdu_buffer,
                                IO_APDU_BUFFER_SIZE,
                                &length,
                                &privateKey);

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