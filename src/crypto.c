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
#include <bech32.h>
#include "crypto.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "apdu_codes.h"
#include "coin.h"
#include "zxmacros.h"
#include "common/tx.h"

//////////

uint32_t hdPath[HDPATH_LEN_DEFAULT];

// the last "viewed" bip32 path is an extra check for security,
// to ensure that the user has "seen" the address they are using before signing.
// the app must have validated it (validate_bnc_bip32).
uint8_t viewed_bip32_depth;
uint32_t viewed_bip32_path[HDPATH_LEN_DEFAULT];

uint8_t bech32_hrp_len;
char bech32_hrp[MAX_BECH32_HRP_LEN + 1];

int sign_secp256k1(const uint8_t *message,
                   unsigned int message_length,
                   uint8_t *signature,
                   size_t *signature_length) {
    unsigned int info = 0;
    uint8_t message_digest[CX_SHA256_SIZE] = {0};
        
    cx_hash_sha256(message, message_length, message_digest, CX_SHA256_SIZE);

    if(bip32_derive_ecdsa_sign_hash_256(CX_CURVE_256K1,
                                    hdPath,
                                    HDPATH_LEN_DEFAULT,
                                    CX_RND_RFC6979 | CX_LAST,
                                    CX_SHA256,
                                    message_digest,
                                    CX_SHA256_SIZE,
                                    signature,
                                    signature_length,
                                    &info) != CX_OK)
    {
        THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
    }

#ifdef TESTING_ENABLED
    return cx_ecdsa_verify(
            &publicKey,
            CX_LAST,
            CX_SHA256,
            message_digest,
            CX_SHA256_SIZE,
            signature,
            *signature_length);
#else
    return 1;
#endif
}

__Z_INLINE zxerr_t compressPubkey(const uint8_t *pubkey, uint16_t pubkeyLen, uint8_t *output, uint16_t outputLen) {
    if (pubkey == NULL || output == NULL ||
        pubkeyLen != PK_LEN_SECP256K1_UNCOMPRESSED || outputLen < PK_LEN_SECP256K1) {
            return zxerr_unknown;
    }

    // Format pubkey
    for (int i = 0; i < 32; i++) {
        output[i] = pubkey[64 - i];
    }
    if ((pubkey[32] & 1) != 0) {
        output[31] |= 0x80;
    }

    MEMCPY(output, pubkey, PK_LEN_SECP256K1);
    output[0] = pubkey[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    return zxerr_ok;
}

void set_hrp(char *hrp) {
    strncpy(bech32_hrp, hrp, sizeof(bech32_hrp));
    bech32_hrp_len = strlen(bech32_hrp);
}

bool validate_bnc_hrp(void) {
    // only accept known bnc hrps
    if (strcmp("bnb", bech32_hrp) != 0 && strcmp("tbnb", bech32_hrp) != 0) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    return 1;
}

void ripemd160_32(uint8_t *out, uint8_t *in) {
    cx_ripemd160_t rip160;
    cx_ripemd160_init(&rip160);
    cx_hash_no_throw(&rip160.header, CX_LAST, in, CX_SHA256_SIZE, out, CX_RIPEMD160_SIZE);
}

void crypto_set_hrp(char *p) {
    bech32_hrp_len = strlen(p);
    if (bech32_hrp_len < MAX_BECH32_HRP_LEN) {
        snprintf(bech32_hrp, sizeof(bech32_hrp), "%s", p);
    }
}

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrResponseLen) {
    if (buffer_len < PK_LEN_SECP256K1 + 50) {
        return zxerr_buffer_too_small;
    }

    // extract pubkey
    uint8_t uncompressedPubkey [PK_LEN_SECP256K1_UNCOMPRESSED] = {0};

    if(bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                hdPath,
                                HDPATH_LEN_DEFAULT,
                                uncompressedPubkey,
                                NULL,
                                CX_SHA512)  != CX_OK)
    {
        THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
    }
    
    CHECK_ZXERR(compressPubkey(uncompressedPubkey, sizeof(uncompressedPubkey), buffer, buffer_len))

    char *addr = (char *) (buffer + PK_LEN_SECP256K1);

    uint8_t hashed1_pk[CX_SHA256_SIZE] = {0};

    // Hash it
    cx_hash_sha256(buffer, PK_LEN_SECP256K1, hashed1_pk, CX_SHA256_SIZE);
    uint8_t hashed2_pk[CX_RIPEMD160_SIZE];
    ripemd160_32(hashed2_pk, hashed1_pk);

    CHECK_ZXERR(bech32EncodeFromBytes(addr, buffer_len - PK_LEN_SECP256K1, bech32_hrp, hashed2_pk, CX_RIPEMD160_SIZE, 1, BECH32_ENCODING_BECH32))
    *addrResponseLen = PK_LEN_SECP256K1 + strnlen(addr, (buffer_len - PK_LEN_SECP256K1));
    return zxerr_ok;
}