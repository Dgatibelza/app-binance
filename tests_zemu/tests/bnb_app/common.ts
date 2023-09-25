/** ******************************************************************************
 *  (c) 2018 - 2022 Ledger SA
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
 ******************************************************************************* */

export const CLA = 0xbc
export const CHUNK_SIZE = 250
export const APP_KEY = 'CSM'

export const INS = {
  GET_VERSION: 0x00,
  INS_PUBLIC_KEY_SECP256K1: 0x01, // Obsolete
  SIGN_SECP256K1: 0x02,
  SHOW_ADDR_SECP256K1: 0x03,
  GET_ADDR_SECP256K1: 0x04,
}

export const PAYLOAD_TYPE = {
  INIT: 0x00,
  ADD: 0x01,
  LAST: 0x02,
}

export const ERROR_CODE = {
  NoError: 0x9000,
}

const ERROR_DESCRIPTION: any = {
  0x9000: 'No errors',
  0x9001: 'Device is busy',
  0x6400: 'Execution Error',
  0x6982: 'Empty Buffer',
  0x6983: 'Output buffer too small',
  0x6984: 'Data is invalid',
  0x6985: 'Conditions not satisfied',
  0x6986: 'Command not allowed',
  0x6987: 'Transaction not initialized',
  0x6a80: 'Bad key handle',
  0x6b00: 'Invalid P1/P2',
  0x6d00: 'Instruction not supported',
  0x6e00: 'CLA not supported',
  0x6f00: 'Unknown error',
  0x6f01: 'Sign/verify error',
}

export function errorCodeToString(statusCode: number) {
  if (statusCode in ERROR_DESCRIPTION) return ERROR_DESCRIPTION[statusCode]
  return `Unknown Status Code: ${statusCode}`
}

function isDict(v: any) {
  return typeof v === 'object' && v !== null && !(v instanceof Array) && !(v instanceof Date)
}

export function processErrorResponse(response: any) {
  if (response) {
    if (isDict(response)) {
      if (Object.prototype.hasOwnProperty.call(response, 'statusCode')) {
        return {
          return_code: response.statusCode,
          error_message: errorCodeToString(response.statusCode),
        }
      }

      if (
        Object.prototype.hasOwnProperty.call(response, 'return_code') &&
        Object.prototype.hasOwnProperty.call(response, 'error_message')
      ) {
        return response
      }
    }
    return {
      return_code: 0xffff,
      error_message: response.toString(),
    }
  }

  return {
    return_code: 0xffff,
    error_message: response.toString(),
  }
}

export async function getVersion(transport: any) {
  return transport.send(CLA, INS.GET_VERSION, 0, 0).then((response: any) => {
    const errorCodeData = response.slice(-2)
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
    return {
      return_code: returnCode,
      error_message: errorCodeToString(returnCode),
      // ///
      test_mode: response[0] !== 0,
      major: response[1],
      minor: response[2],
      patch: response[3],
      device_locked: response[4] === 1,
    }
  }, processErrorResponse)
}
