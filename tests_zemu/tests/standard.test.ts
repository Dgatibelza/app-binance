/** ******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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

import Zemu, { zondaxMainmenuNavigation, ButtonKind, ClickNavigation, TouchNavigation } from '@zondax/zemu'
import { BNBApp } from './bnb_app/bnbApp'
import { defaultOptions, DEVICE_MODELS, APP_SEED, example_tx_str_basic, example_tx_str_basic2, ibc_denoms } from './common'
import { Secp256k1HdWallet } from '@cosmjs/launchpad'
import { stringToPath } from '@cosmjs/crypto'
// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'
import { ActionKind, IButton, INavElement } from '@zondax/zemu/dist/types'

jest.setTimeout(90000)

describe('Standard', function () {
  test.concurrent.each(DEVICE_MODELS)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BNBApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('test_mode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
      expect(resp).toHaveProperty('device_locked')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('get public key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BNBApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 714, 0, 0, 0]
      const resp = await app.publicKey(path)

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('uncompressed_pk')
      expect(resp.uncompressed_pk.length).toEqual(65)

      const slip10Path = stringToPath("m/44'/714'/0'/0/0")

      const wallet = await Secp256k1HdWallet.fromMnemonic(APP_SEED, { hdPaths: [slip10Path], prefix: 'bnb' })
      const [{ pubkey }] = await wallet.getAccounts()

      const elliptic = require('elliptic')
      const ec = new elliptic.ec('secp256k1')
      const publicKeyUncompressed = ec.keyFromPublic(pubkey, 'hex').getPublic(false, 'hex')

      expect(resp.uncompressed_pk.toString('hex')).toEqual(publicKeyUncompressed)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new BNBApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 714, 0, 0, 0]
      const resp = await app.getAddressAndPubKey(path, 'bnb')

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')

      expect(resp).toHaveProperty('bech32_address')
      expect(resp).toHaveProperty('compressed_pk')

      // Take the compressed pubkey and verify that the expected address can be computed
      const bnbAddress = app.getBech32FromPK('bnb', resp.compressed_pk)
      expect(resp.bech32_address).toEqual(bnbAddress) // Should be 'bnb146utes2zglcgnntwnk69wmepwsudkzd8909sx2'
      expect(resp.compressed_pk.length).toEqual(33)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new BNBApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 714, 0, 0, 0]
      const respRequest = app.showAddressAndPubKey(path, 'bnb')
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  //   test.concurrent.each(DEVICE_MODELS)('show address HUGE', async function (m) {
  //     const sim = new Zemu(m.path)
  //     try {
  //       await sim.start({
  //         ...defaultOptions,
  //         model: m.name,
  //         approveKeyword: m.name === 'stax' ? 'QR' : '',
  //         approveAction: ButtonKind.ApproveTapButton,
  //       })
  //       const app = new BNBApp(sim.getTransport())

  //       // Derivation path. First 3 items are automatically hardened!
  //       const path = [44, 714, 2147483647, 0, 4294967295]
  //       const resp = await app.showAddressAndPubKey(path, 'bnb')
  //       console.log(resp)

  //       expect(resp.return_code).toEqual(0x6985)
  //       expect(resp.error_message).toEqual('Conditions not satisfied')
  //     } finally {
  //       await sim.close()
  //     }
  //   })

  //   test.concurrent.each(DEVICE_MODELS)('show address HUGE Expect', async function (m) {
  //     const sim = new Zemu(m.path)
  //     try {
  //       await sim.start({
  //         ...defaultOptions,
  //         model: m.name,
  //         approveKeyword: m.name === 'stax' ? 'Path' : '',
  //         approveAction: ButtonKind.ApproveTapButton,
  //       })
  //       const app = new BNBApp(sim.getTransport())

  //       // Activate expert mode
  //       await sim.toggleExpertMode();

  //       // Derivation path. First 3 items are automatically hardened!
  //       const path = [44, 714, 2147483647, 0, 4294967295]
  //       const respRequest = app.showAddressAndPubKey(path, 'bnb')

  //       // Wait until we are not in the main menu
  //       await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //       await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_huge`)

  //       const resp = await respRequest
  //       console.log(resp)

  //       expect(resp.return_code).toEqual(0x9000)
  //       expect(resp.error_message).toEqual('No errors')

  //       expect(resp).toHaveProperty('bech32_address')
  //       expect(resp).toHaveProperty('compressed_pk')

  //       expect(resp.bech32_address).toEqual('cosmos1ex7gkwwmq4vcgdwcalaq3t20pgwr37u6ntkqzh')
  //       expect(resp.compressed_pk.length).toEqual(33)
  //     } finally {
  //       await sim.close()
  //     }
  //   })

  //   test.concurrent.each(DEVICE_MODELS)('sign basic normal', async function (m) {
  //     const sim = new Zemu(m.path)
  //     try {
  //       await sim.start({ ...defaultOptions, model: m.name })
  //       const app = new BNBApp(sim.getTransport())

  //       const path = [44, 714, 0, 0, 0]
  //       const tx = Buffer.from(JSON.stringify(example_tx_str_basic), "utf-8")

  //       // get address / publickey
  //       const respPk = await app.getAddressAndPubKey(path, 'bnb')
  //       expect(respPk.return_code).toEqual(0x9000)
  //       expect(respPk.error_message).toEqual('No errors')
  //       console.log(respPk)

  //       // do not wait here..
  //       const signatureRequest = app.sign(path, tx)

  //       // Wait until we are not in the main menu
  //       await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //       await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_basic`)

  //       const resp = await signatureRequest
  //       console.log(resp)

  //       expect(resp.return_code).toEqual(0x9000)
  //       expect(resp.error_message).toEqual('No errors')
  //       expect(resp).toHaveProperty('signature')

  //       // Now verify the signature
  //       const hash = crypto.createHash('sha256')
  //       const msgHash = Uint8Array.from(hash.update(tx).digest())

  //       const signatureDER = resp.signature
  //       const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

  //       const pk = Uint8Array.from(respPk.compressed_pk)

  //       const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
  //       expect(signatureOk).toEqual(true)
  //     } finally {
  //       await sim.close()
  //     }
  //   })

  //   test.concurrent.each(DEVICE_MODELS)('sign basic normal2', async function (m) {
  //     const sim = new Zemu(m.path)
  //     try {
  //       await sim.start({ ...defaultOptions, model: m.name })
  //       const app = new BNBApp(sim.getTransport())

  //       const path = [44, 714, 0, 0, 0]
  //       const tx = Buffer.from(JSON.stringify(example_tx_str_basic2), "utf-8")

  //       // get address / publickey
  //       const respPk = await app.getAddressAndPubKey(path, 'bnb')
  //       expect(respPk.return_code).toEqual(0x9000)
  //       expect(respPk.error_message).toEqual('No errors')
  //       console.log(respPk)

  //       // do not wait here..
  //       const signatureRequest = app.sign(path, tx)

  //       // Wait until we are not in the main menu
  //       await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //       await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_basic2`)

  //       const resp = await signatureRequest
  //       console.log(resp)

  //       expect(resp.return_code).toEqual(0x9000)
  //       expect(resp.error_message).toEqual('No errors')

  //       // Now verify the signature
  //       const hash = crypto.createHash('sha256')
  //       const msgHash = Uint8Array.from(hash.update(tx).digest())

  //       const signatureDER = resp.signature
  //       const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

  //       const pk = Uint8Array.from(respPk.compressed_pk)

  //       const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
  //       expect(signatureOk).toEqual(true)
  //     } finally {
  //       await sim.close()
  //     }
  //   })

  //   test.concurrent.each(DEVICE_MODELS)('sign basic with extra fields', async function (m) {
  //     const sim = new Zemu(m.path)
  //     try {
  //       await sim.start({ ...defaultOptions, model: m.name })
  //       const app = new BNBApp(sim.getTransport())

  //       const path = [44, 714, 0, 0, 0]
  //       const tx = Buffer.from(JSON.stringify(example_tx_str_basic), "utf-8")

  //       // get address / publickey
  //       const respPk = await app.getAddressAndPubKey(path, 'bnb')
  //       expect(respPk.return_code).toEqual(0x9000)
  //       expect(respPk.error_message).toEqual('No errors')
  //       console.log(respPk)

  //       // do not wait here..
  //       const signatureRequest = app.sign(path, tx)

  //       // Wait until we are not in the main menu
  //       await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //       await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_basic_extra_fields`)

  //       const resp = await signatureRequest
  //       console.log(resp)

  //       expect(resp.return_code).toEqual(0x9000)
  //       expect(resp.error_message).toEqual('No errors')
  //       expect(resp).toHaveProperty('signature')

  //       // Now verify the signature
  //       const hash = crypto.createHash('sha256')
  //       const msgHash = Uint8Array.from(hash.update(tx).digest())

  //       const signatureDER = resp.signature
  //       const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

  //       const pk = Uint8Array.from(respPk.compressed_pk)

  //       const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
  //       expect(signatureOk).toEqual(true)
  //     } finally {
  //       await sim.close()
  //     }
  //   })
})
