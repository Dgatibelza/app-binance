/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 ZondaX GmbH
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
#pragma once

#include "os.h"
#include "coin.h"
#include "zxerror.h"


/// keys_secp256k1
/// \param publicKey
/// \param privateKey
/// \param privateKeyData
void keys_secp256k1(cx_ecfp_public_key_t *publicKey,
                    cx_ecfp_private_key_t *privateKey,
                    const uint8_t privateKeyData[32]);

/// sign_secp256k1
/// \param message
/// \param message_length
/// \param signature
/// \param signature_capacity
/// \param signature_length
/// \param privateKey
/// \return
int sign_secp256k1(const uint8_t *message,
                   unsigned int message_length,
                   uint8_t *signature,
                   unsigned int signature_capacity,
                   unsigned int *signature_length,
                   cx_ecfp_private_key_t *privateKey);

void crypto_set_hrp(char *p);

void set_hrp(char *hrp);

bool validate_bnc_hrp(void);

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

// extern uint8_t bip32_depth;
// extern uint32_t bip32_path[5];

extern uint8_t viewed_bip32_depth;
extern uint32_t viewed_bip32_path[5];

extern uint8_t bech32_hrp_len;
extern char bech32_hrp[MAX_BECH32_HRP_LEN + 1];

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrResponseLen);

// uint16_t crypto_sign(uint8_t *signature,
//                      uint16_t signatureMaxlen,
//                      const uint8_t *message,
//                      uint16_t messageLen);