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
#include "addr.h"
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



int tx_getData(
        char *title, int max_title_length,
        char *key, int max_key_length,
        char *value, int max_value_length,
        int page_index,
        int chunk_index,
        int *page_count_out,
        int *chunk_count_out) {

    *page_count_out = transaction_get_display_pages();

    switch (current_sigtype) {
        case SECP256K1:
            snprintf(title, max_title_length, "PREVIEW - %02d/%02d", page_index + 1, *page_count_out);
            break;
        default:
            snprintf(title, max_title_length, "INVALID!");
            break;
    }

    *chunk_count_out = transaction_get_display_key_value(
            key, max_key_length,
            value, max_value_length,
            page_index, chunk_index);

    return 0;
}

void tx_accept_sign() {
    // Generate keys
    cx_ecfp_public_key_t publicKey;
    cx_ecfp_private_key_t privateKey;
    uint8_t privateKeyData[32];

    unsigned int length = 0;
    int result = 0;
    switch (current_sigtype) {
        case SECP256K1:
            os_perso_derive_node_bip32(
                    CX_CURVE_256K1,
                    bip32_path, bip32_depth,
                    privateKeyData, NULL);

            keys_secp256k1(&publicKey, &privateKey, privateKeyData);
            memset(privateKeyData, 0, 32);

            result = sign_secp256k1(
                    transaction_get_buffer(),
                    transaction_get_buffer_length(),
                    G_io_apdu_buffer,
                    IO_APDU_BUFFER_SIZE,
                    &length,
                    &privateKey);
            break;
        default:
            THROW(APDU_CODE_INS_NOT_SUPPORTED);
            break;
    }
    if (result == 1) {
        set_code(G_io_apdu_buffer, length, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, length + 2);
        view_display_signing_success();
    } else {
        set_code(G_io_apdu_buffer, length, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, length + 2);
        view_display_signing_error();
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
            bip32_path, bip32_depth,
            privateKeyData, NULL);
    keys_secp256k1(publicKey, &privateKey, privateKeyData);
    memset(privateKeyData, 0, sizeof(privateKeyData));
    memset(&privateKey, 0, sizeof(privateKey));
}

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
                    
    ///////////////////

    uint8_t len = extractHRP(rx, OFFSET_DATA);
    
    // Parse arguments
    if (!validate_bnc_hrp()) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    
    // extractHDPath(rx, OFFSET_DATA + 1 + len);
    
    if (!extract_bip32(&bip32_depth, bip32_path, rx, OFFSET_DATA + bech32_hrp_len + 1)) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (!validate_bnc_bip32(bip32_depth, bip32_path)) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    // if (requireConfirmation) {
    //     app_fill_address(addr_secp256k1);
    //     view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
    //     view_review_show(REVIEW_ADDRESS);
    //     *flags |= IO_ASYNCH_REPLY;
    //     return;
    // }

    // *tx = app_fill_address(addr_secp256k1);
    THROW(APDU_CODE_OK);
                    
                    
    ///////                
                    

    // view_set_handlers(addr_getData, addr_accept, addr_reject);
    // view_addr_confirm(bip32_path[4] & 0x7FFFFFF);

    // // must be the last bip32 the user "saw" for signing to work.
    // memcpy(viewed_bip32_path, bip32_path, sizeof(viewed_bip32_path));

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
                    break;
                }

                // INS_PUBLIC_KEY_SECP256K1 will be deprecated in the near future
                case INS_PUBLIC_KEY_SECP256K1: {
                    if (!extract_bip32(&bip32_depth, bip32_path, rx, OFFSET_DATA)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }
                    if (!validate_bnc_bip32(bip32_depth, bip32_path)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }

                    cx_ecfp_public_key_t publicKey;
                    get_pubkey(&publicKey);

                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    *tx += 65;

                    // NOTE: REMOVED FOR SECURITY - this does not show the address to user.
                    // memcpy(viewed_bip32_path, bip32_path, sizeof(viewed_bip32_path));

                    THROW(APDU_CODE_OK);
                    break;
                }

                case INS_SHOW_ADDR_SECP256K1: {
                    // Parse arguments
                    extractHRP(rx, OFFSET_DATA);

                    if (!validate_bnc_hrp()) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }
                    if (!extract_bip32(&bip32_depth, bip32_path, rx, OFFSET_DATA + bech32_hrp_len + 1)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }
                    if (!validate_bnc_bip32(bip32_depth, bip32_path)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }

                    view_set_handlers(addr_getData_onePage, NULL, NULL);
                    view_addr_show(bip32_path[4] & 0x7FFFFFF);

                    // must be the last bip32 the user "saw" for signing to work.
                    memcpy(viewed_bip32_path, bip32_path, sizeof(viewed_bip32_path));

                    *flags |= IO_ASYNCH_REPLY;
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    // Parse arguments
                    extractHRP(rx, OFFSET_DATA);
                    
                    if (!validate_bnc_hrp()) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }
                    if (!extract_bip32(&bip32_depth, bip32_path, rx, OFFSET_DATA + bech32_hrp_len + 1)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }
                    if (!validate_bnc_bip32(bip32_depth, bip32_path)) {
                        THROW(APDU_CODE_DATA_INVALID);
                    }

                    view_set_handlers(addr_getData, addr_accept, addr_reject);
                    view_addr_confirm(bip32_path[4] & 0x7FFFFFF);

                    // must be the last bip32 the user "saw" for signing to work.
                    memcpy(viewed_bip32_path, bip32_path, sizeof(viewed_bip32_path));

                    *flags |= IO_ASYNCH_REPLY;
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    current_sigtype = SECP256K1;
                    if (!process_chunk(tx, rx, true))
                        THROW(APDU_CODE_OK);

                    const char *error_msg = transaction_parse();
                    if (error_msg != NULL) {
                        int error_msg_length = strlen(error_msg);
                        os_memmove(G_io_apdu_buffer, error_msg, error_msg_length);
                        *tx += (error_msg_length);
                        THROW(APDU_CODE_BAD_KEY_HANDLE);
                    }

                    view_set_handlers(tx_getData, tx_accept_sign, tx_reject);
                    view_tx_show(0);

                    *flags |= IO_ASYNCH_REPLY;
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