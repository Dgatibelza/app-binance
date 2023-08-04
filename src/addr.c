/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

#include <stdio.h>
#include "coin.h"
#include "zxerror.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "crypto.h"
#include "app_main.h"

#include "view_common.h"

// zxerr_t addr_getNumItems(uint8_t *num_items) {
//     zemu_log_stack("addr_getNumItems");
//     *num_items = 1;
//     if (app_mode_expert()) {
//         *num_items = 2;
//     }
//     return zxerr_ok;
// }

// zxerr_t addr_getItem(int8_t displayIdx,
//                      char *outKey, uint16_t outKeyLen,
//                      char *outVal, uint16_t outValLen,
//                      uint8_t pageIdx, uint8_t *pageCount) {
//     ZEMU_LOGF(200, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

//     switch (displayIdx) {
//         case 0:
//             snprintf(outKey, outKeyLen, "Address");
//             pageString(outVal, outValLen, (char *) (G_io_apdu_buffer + PK_LEN_SECP256K1), pageIdx, pageCount);
//             return zxerr_ok;
//         case 1: {
//             if (!app_mode_expert()) {
//                 return zxerr_no_data;
//             }

//             snprintf(outKey, outKeyLen, "Your Path");
//             char buffer[300];
//             bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
//             pageString(outVal, outValLen, buffer, pageIdx, pageCount);
//             return zxerr_ok;
//         }
//         default:
//             return zxerr_no_data;
//     }
// }

#define PK_COMPRESSED_LEN 33


void get_pk_compressed(uint8_t *pkc) {
    cx_ecfp_public_key_t publicKey;
    // Modify the last part of the path
    get_pubkey(&publicKey);
    // "Compress" public key in place
    publicKey.W[0] = publicKey.W[64] & 1 ? 0x03 : 0x02;
    memcpy(pkc, publicKey.W, PK_COMPRESSED_LEN);
}

int addr_getData(char *title, int max_title_length,
                 char *key, int max_key_length,
                 char *value, int max_value_length,
                 int page_index,
                 int chunk_index,
                 int *page_count_out,
                 int *chunk_count_out) {

    *page_count_out = 0x7FFFFFFF;
    *chunk_count_out = 1;

    snprintf(title, max_title_length, "Account %d", bip32_path[2] & 0x7FFFFFF);
    snprintf(key, max_key_length, "Address %d", page_index);

    bip32_path[bip32_depth - 1] = page_index;
    uint8_t tmp[PK_COMPRESSED_LEN];
    get_pk_compressed(tmp);

    // Convert pubkey to address
    uint8_t hashed_pk[CX_RIPEMD160_SIZE];
    cx_hash_sha256(tmp, PK_COMPRESSED_LEN, tmp, CX_SHA256_SIZE);
    ripemd160_32(hashed_pk, tmp);

    // Convert address to bech32
    // bech32EncodeFromBytes(value, bech32_hrp, hashed_pk, CX_RIPEMD160_SIZE);

    return 0;
}

int addr_getData_onePage(char *title, int max_title_length,
                 char *key, int max_key_length,
                 char *value, int max_value_length,
                 int page_index,
                 int chunk_index,
                 int *page_count_out,
                 int *chunk_count_out) {
    int ret = addr_getData(title, max_title_length, key, max_key_length, value, max_value_length, page_index, chunk_index, page_count_out, chunk_count_out);
    *page_count_out = 1;
    *chunk_count_out = 1;
    return ret;
}

void addr_accept() {
    int pos = 0;
    // Send pubkey
    get_pk_compressed(G_io_apdu_buffer + pos);
    pos += PK_COMPRESSED_LEN;

    // Send bech32 addr
    strcpy((char *) (G_io_apdu_buffer + pos), (char *) viewctl_DataValue);
    pos += strlen((char *) viewctl_DataValue);

    set_code(G_io_apdu_buffer, pos, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, pos + 2);
    view_idle_show(0,NULL);
}

void addr_reject() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    view_idle_show(0,NULL);
}

void show_addr_exit() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    view_idle_show(0,NULL);
}