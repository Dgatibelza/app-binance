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
import { defaultOptions, DEVICE_MODELS, APP_SEED } from './common'
import { Secp256k1HdWallet } from '@cosmjs/launchpad'
import { stringToPath } from '@cosmjs/crypto'
// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'
import { ActionKind, IButton, INavElement } from '@zondax/zemu/dist/types'

jest.setTimeout(90000)

describe('Standard', function () {
  test.each(DEVICE_MODELS)('can start and stop container ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
    } finally {
      await sim.close()
      expect(true).toEqual(true)
    }
  })

  test.each(DEVICE_MODELS)('main menu ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const nav = zondaxMainmenuNavigation(dev.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${dev.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
      expect(true).toEqual(true)
    }
  })

  test.each(DEVICE_MODELS)('get app version ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())
      const resp = await app.getVersion()

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

  test.each(DEVICE_MODELS)('get public key ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
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

  test.each(DEVICE_MODELS)('get address ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
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

  test.each(DEVICE_MODELS)('show address ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: dev.name,
        approveKeyword: dev.name === 'stax' || dev.name === 'flex' ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new BNBApp(sim.getTransport())

      // Derivation path. First 3 items are automatically hardened!
      const path = [44, 714, 0, 0, 0]
      const respRequest = app.showAddressAndPubKey(path, 'bnb')
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${dev.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('sign basic normal ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      //   const tx_str_basic = `{"account_number":"12","chain_id":"bnbchain","data":null,"memo":"smiley!☺","msgs":[{"id":"BA36F0FAD74D8F41045463E4774F328F4AF779E5-4","ordertype":2,"price":1.612345678,"quantity":123.456,"sender":"bnc1hgm0p7khfk85zpz5v0j8wnej3a90w7098fpxyh","side":1,"symbol":"NNB-338_BNB","timeinforce":3}],"sequence":"3","source":"1"}`
      const tx_str_basic = `{"account_number":"1","chain_id":"Binance-Chain-Tigris","data":"DATA","memo":"MEMO","msgs":[{"inputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":"10000000000","denom":"BNB"}]}],"outputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":10000000000,"denom":"BNB"}]}]}],"sequence":"2","source":"1"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')
      console.log(respPk)

      // do not wait here..
      const signatureRequest = app.sign(path, tx)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${dev.prefix.toLowerCase()}-sign_basic`)

      const resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      console.log(resp)

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('sign basic expert ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      //   const tx_str_basic = `{"account_number":"12","chain_id":"bnbchain","data":null,"memo":"smiley!☺","msgs":[{"id":"BA36F0FAD74D8F41045463E4774F328F4AF779E5-4","ordertype":2,"price":1.612345678,"quantity":123.456,"sender":"bnc1hgm0p7khfk85zpz5v0j8wnej3a90w7098fpxyh","side":1,"symbol":"NNB-338_BNB","timeinforce":3}],"sequence":"3","source":"1"}`
      const tx_str_basic = `{"account_number":"1","chain_id":"Binance-Chain-Tigris","data":"DATA","memo":"MEMO","msgs":[{"inputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":"10000000000","denom":"BNB"}]}],"outputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":10000000000,"denom":"BNB"}]}]}],"sequence":"2","source":"1"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // Toggle expert mode
      await sim.toggleExpertMode()

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')
      console.log(respPk)

      // do not wait here..
      const signatureRequest = app.sign(path, tx)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${dev.prefix.toLowerCase()}-sign_basic_expert`)

      const resp = await signatureRequest
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      console.log(resp)

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('sign tx msgs depth level > 2 ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      const tx_str_basic = `{"account_number":"1","chain_id":"Binance-Chain-Tigris","data":"DATA","memo":"MEMO","msgs":[{"level 1":[{"level 2":[{"level 3":"toto"}]}]}],"sequence":"2","source":"1"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')

      // do not wait here..
      const signatureRequest = app.sign(path, tx)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${dev.prefix.toLowerCase()}-sign_max_depth`)

      const resp = await signatureRequest

      //   expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('wrong tx with missing mandatory field ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      const tx_str_basic = `{"account_number":"1","chain_id":"Binance-Chain-Tigris","data":"DATA","memo":"MEMO","msgs":[{"inputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":"10000000000","denom":"BNB"}]}],"outputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":10000000000,"denom":"BNB"}]}]}],"sequence":"2"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')

      const resp = await app.sign(path, tx)

      expect(resp.return_code).toEqual(0x6984)
      expect(resp.error_message).toEqual('Data is invalid : JSON Missing data')
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('wrong tx with white space in corpus ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      const tx_str_basic = `{ "account_number":"1","chain_id":"Binance-Chain-Tigris","data":"DATA","memo":"MEMO","msgs":[{"inputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":"10000000000","denom":"BNB"}]}],"outputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":10000000000,"denom":"BNB"}]}]}],"sequence":"2"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')

      const resp = await app.sign(path, tx)

      expect(resp.return_code).toEqual(0x6984)
      expect(resp.error_message).toEqual('Data is invalid : JSON Contains whitespace in the corpus')
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('wrong tx with keys unsorted ($dev.name)', async ({ dev }) => {
    const sim = new Zemu(dev.path)
    try {
      await sim.start({ ...defaultOptions, model: dev.name })
      const app = new BNBApp(sim.getTransport())

      const path = [44, 714, 0, 0, 0]
      const tx_str_basic = `{"chain_id":"Binance-Chain-Tigris","account_number":"1","data":"DATA","memo":"MEMO","msgs":[{"inputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":"10000000000","denom":"BNB"}]}],"outputs":[{"address":"bnb1hlly02l6ahjsgxw9wlcswnlwdhg4xhx3f309d9","coins":[{"amount":10000000000,"denom":"BNB"}]}]}],"sequence":"2"}`
      const tx = Buffer.from(tx_str_basic, 'utf-8')

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'bnb')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')

      const resp = await app.sign(path, tx)

      expect(resp.return_code).toEqual(0x6984)
      expect(resp.error_message).toEqual('Data is invalid : JSON Dictionaries are not sorted')
    } finally {
      await sim.close()
    }
  })
})
