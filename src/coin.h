/*******************************************************************************
*  (c) 2023 Ledger SAS
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
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define CLA                       0xBC

#define OFFSET_PCK_INDEX          2  //< Package index offset
#define OFFSET_PCK_COUNT          3  //< Package count offset

#ifdef INS_GET_VERSION
#undef INS_GET_VERSION
#endif 

#define INS_GET_VERSION           0
#define INS_PUBLIC_KEY_SECP256K1  1  // It will be deprecated in the near future
#define INS_SIGN_SECP256K1        2
#define INS_SHOW_ADDR_SECP256K1   3
#define INS_GET_ADDR_SECP256K1    4

#ifdef TESTING_ENABLED
#define INS_HASH_TEST                   100
#define INS_PUBLIC_KEY_SECP256K1_TEST   101
#define INS_SIGN_SECP256K1_TEST         102
#endif

#define HDPATH_LEN_DEFAULT        5

#define HDPATH_0_DEFAULT          (0x80000000u | 0x2cu) // 0x80000000u | 44u
#define HDPATH_1_DEFAULT          (0x80000000u | 0x2cau) // 0x80000000u | 714u
#define HDPATH_2_DEFAULT          (0x80000000u | 0u)
#define HDPATH_3_DEFAULT          (0u)
#define HDPATH_4_DEFAULT          (0u)

#define MAX_BECH32_HRP_LEN        5

#define PK_LEN_SECP256K1                33u
#define PK_LEN_SECP256K1_UNCOMPRESSED   65u

typedef enum {
    addr_secp256k1 = 0,
} address_kind_e;

#define VIEW_ADDRESS_OFFSET_SECP256K1       PK_LEN_SECP256K1
#define VIEW_ADDRESS_LAST_PAGE_DEFAULT      0

#define MENU_MAIN_APP_LINE1                "Binance Chain"
#define MENU_MAIN_APP_LINE2                "Ready"
#define APPVERSION_LINE1                   "Version:"
#define APPVERSION_LINE2                   ("v" APPVERSION)

#define CRYPTO_BLOB_SKIP_BYTES              0
#define COIN_DEFAULT_CHAINID                "Binance-Chain-Tigris"

#define COIN_DEFAULT_DENOM_FACTOR           8
#define COIN_DEFAULT_DENOM_TRIMMING         8

// Coin denoms may be up to 128 characters long
// https://github.com/cosmos/cosmos-sdk/blob/master/types/coin.go#L780
// https://github.com/cosmos/ibc-go/blob/main/docs/architecture/adr-001-coin-source-tracing.md
#define COIN_DENOM_MAXSIZE                  129
#define COIN_AMOUNT_MAXSIZE                 50

#define COIN_MAX_CHAINID_LEN                30
#define INDEXING_TMP_KEYSIZE 70
#define INDEXING_TMP_VALUESIZE 70
#define INDEXING_GROUPING_REF_TYPE_SIZE 70
#define INDEXING_GROUPING_REF_FROM_SIZE 70

#define MENU_MAIN_APP_LINE2_SECRET         "?"
#define COIN_SECRET_REQUIRED_CLICKS         0

#ifdef __cplusplus
}
#endif







