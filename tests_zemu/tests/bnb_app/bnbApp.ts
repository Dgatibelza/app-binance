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
import { CHUNK_SIZE, CLA, INS, errorCodeToString, getVersion, processErrorResponse, ERROR_CODE } from './common'

import Transport from '@ledgerhq/hw-transport'
import { bech32 } from 'bech32'
const crypto = require('crypto')
// const bech32 = require('bech32')
const Ripemd160 = require('ripemd160')

export class BNBApp {
  transport: Transport
  versionResponse?: any

  constructor(transport: any) {
    if (!transport) {
      throw new Error('Transport has not been defined')
    }

    this.transport = transport
  }

  static serializeHRP(hrp: string) {
    if (hrp == null || hrp.length < 3 || hrp.length > 83) {
      throw new Error('Invalid HRP')
    }
    const buf = Buffer.alloc(1 + hrp.length)
    buf.writeUInt8(hrp.length, 0)
    buf.write(hrp, 1)
    return buf
  }

  getBech32FromPK(hrp: string, pk: Buffer) {
    if (pk.length !== 33) {
      throw new Error('expected compressed public key [31 bytes]')
    }
    const hashSha256 = crypto.createHash('sha256').update(pk).digest()
    const hashRip = new Ripemd160().update(hashSha256).digest()
    return bech32.encode(hrp, bech32.toWords(hashRip))
  }

  async signGetChunks(path: number[], buffer: Buffer) {
    const serializedPath = await this.serializePath(path)

    const chunks = []
    chunks.push(serializedPath)

    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > buffer.length) {
        end = buffer.length
      }
      chunks.push(buffer.slice(i, end))
    }

    return chunks
  }

  async getVersion() {
    try {
      this.versionResponse = await getVersion(this.transport)
      return this.versionResponse
    } catch (e) {
      return processErrorResponse(e)
    }
  }

  async appInfo() {
    return this.transport.send(0xb0, 0x01, 0, 0).then((response: any) => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      let appName = ''
      let appVersion = ''
      let flagLen = 0
      let flagsValue = 0

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        return {
          return_code: 0x9001,
          error_message: 'response format ID not recognized',
        }
      } else {
        const appNameLen = response[1]
        appName = response.slice(2, 2 + appNameLen).toString('ascii')
        let idx = 2 + appNameLen
        const appVersionLen = response[idx]
        idx += 1
        appVersion = response.slice(idx, idx + appVersionLen).toString('ascii')
        idx += appVersionLen
        const appFlagsLen = response[idx]
        idx += 1
        flagLen = appFlagsLen
        flagsValue = response[idx]
      }

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        // eslint-disable-next-line no-bitwise
        flag_recovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_signed_mcu_code: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_onboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flag_pin_validated: (flagsValue & 128) !== 0,
      }
    }, processErrorResponse)
  }

  async deviceInfo() {
    return this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [ERROR_CODE.NoError, 0x6e00]).then((response: any) => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: 'This command is only available in the Dashboard',
        }
      }

      const targetId = response.slice(0, 4).toString('hex')

      let pos = 4
      const secureElementVersionLen = response[pos]
      pos += 1
      const seVersion = response.slice(pos, pos + secureElementVersionLen).toString()
      pos += secureElementVersionLen

      const flagsLen = response[pos]
      pos += 1
      const flag = response.slice(pos, pos + flagsLen).toString('hex')
      pos += flagsLen

      const mcuVersionLen = response[pos]
      pos += 1
      // Patch issue in mcu version
      let tmp = response.slice(pos, pos + mcuVersionLen)
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.slice(pos, pos + mcuVersionLen - 1)
      }
      const mcuVersion = tmp.toString()

      return {
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
        // //
        targetId,
        seVersion,
        flag,
        mcuVersion,
      }
    }, processErrorResponse)
  }

  async serializePath(path: number[]) {
    this.versionResponse = await getVersion(this.transport)

    if (this.versionResponse.return_code !== ERROR_CODE.NoError) {
      throw this.versionResponse
    }

    if (path == null || path.length < 3) {
      throw new Error('Invalid path.')
    }
    if (path.length > 10) {
      throw new Error('Invalid path. Length should be <= 10')
    }
    const buf = Buffer.alloc(1 + 4 * path.length)
    buf.writeUInt8(path.length, 0)
    for (let i = 0; i < path.length; i += 1) {
      let v = path[i]
      if (i < 3) {
        // eslint-disable-next-line no-bitwise
        v |= 0x80000000 // Harden
      }
      buf.writeInt32LE(v, 1 + i * 4)
    }
    return buf
  }

  async getPubKey(data: Buffer) {
    return this.transport.send(CLA, INS.INS_PUBLIC_KEY_SECP256K1, 0, 0, data, [ERROR_CODE.NoError]).then((response: any) => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
      const pk = Buffer.from(response.slice(0, 65))

      return {
        pk,
        uncompressed_pk: pk,
        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
      }
    }, processErrorResponse)
  }

  async publicKey(path: number[]) {
    try {
      const serializedPath = await this.serializePath(path)
      return this.getPubKey(serializedPath)
    } catch (e) {
      return processErrorResponse(e)
    }
  }

  async getAddressAndPubKey(path: number[], hrp: string) {
    return this.serializePath(path)
      .then((serializedPath: Buffer) => {
        const data = Buffer.concat([BNBApp.serializeHRP(hrp), serializedPath])
        return this.transport.send(CLA, INS.GET_ADDR_SECP256K1, 0, 0, data, [ERROR_CODE.NoError]).then((response: any) => {
          const errorCodeData = response.slice(-2)
          const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

          const compressedPk = Buffer.from(response.slice(0, 33))
          const bech32Address = Buffer.from(response.slice(33, -2)).toString()

          return {
            bech32_address: bech32Address,
            compressed_pk: compressedPk,
            return_code: returnCode,
            error_message: errorCodeToString(returnCode),
          }
        }, processErrorResponse)
      })
      .catch(err => processErrorResponse(err))
  }

  async showAddressAndPubKey(path: number[], hrp: string) {
    // return this.getAddressAndPubKey(path, hrp, true)
    return this.serializePath(path)
      .then((serializedPath: Buffer) => {
        const data = Buffer.concat([BNBApp.serializeHRP(hrp), serializedPath])
        return this.transport.send(CLA, INS.SHOW_ADDR_SECP256K1, 0, 0, data, [ERROR_CODE.NoError]).then((response: any) => {
          const errorCodeData = response.slice(0, 2)
          const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
          return {
            return_code: returnCode,
            error_message: errorCodeToString(returnCode),
          }
        }, processErrorResponse)
      })
      .catch(err => processErrorResponse(err))
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer) {
    return this.transport
      .send(CLA, INS.SIGN_SECP256K1, chunkIdx, chunkNum, chunk, [ERROR_CODE.NoError, 0x6984, 0x6a80])
      .then((response: any) => {
        console.log('Signature request response!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        console.log(response)
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (returnCode === 0x6a80 || returnCode === 0x6984) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }

        let signature = null
        if (response.length > 2) {
          signature = response.slice(0, response.length - 2)
        }

        return {
          signature,
          return_code: returnCode,
          error_message: errorMessage,
        }
      }, processErrorResponse)
  }

  async sign(path: number[], buffer: Buffer) {
    return this.signGetChunks(path, buffer).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0]).then(async response => {
        let result = {
          return_code: response.return_code,
          error_message: response.error_message,
          signature: null,
        }

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i])
          if (result.return_code !== ERROR_CODE.NoError) {
            break
          }
        }

        return {
          return_code: result.return_code,
          error_message: result.error_message,
          // ///
          signature: result.signature,
        }
      }, processErrorResponse)
    }, processErrorResponse)
  }
}
