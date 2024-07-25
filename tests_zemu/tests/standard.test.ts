/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
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

import Zemu, { ButtonKind, zondaxMainmenuNavigation, isTouchDevice } from '@zondax/zemu'
import { NamadaApp } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions } from './common'

jest.setTimeout(120000)

const expected_rawpubkey = '0039c1a4bea74c320ab04be5b218369d8c1ae21e41f27edee173ce5e6a51015a4d'
const expected_pubkey = 'tpknam1qquurf975axryz4sf0jmyxpknkxp4cs7g8e8ahhpw089u6j3q9dy6qssdhz'
const expected_address = 'tnam1qq6qyugak0gd4up6lma8z8wr88w3pq9lgvfhw6yu'

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      const mainmenuNavigation = zondaxMainmenuNavigation(m.name)
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, mainmenuNavigation.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get pubkey and address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp = await app.getAddressAndPubKey(hdpath)
      console.log(resp, m.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('pubkey')
      expect(resp).toHaveProperty('address')
      expect(resp).toHaveProperty('rawPubkey')

      expect(resp.rawPubkey.toString('hex')).toEqual(expected_rawpubkey)
      expect(resp.address.toString()).toEqual(expected_address)
      expect(resp.pubkey.toString()).toEqual(expected_pubkey)

    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Pubkey' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new NamadaApp(sim.getTransport())

      const respRequest = app.showAddressAndPubKey(hdpath)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('pubkey')
      expect(resp).toHaveProperty('address')
      expect(resp).toHaveProperty('rawPubkey')

      expect(resp.rawPubkey.toString('hex')).toEqual(expected_rawpubkey)
      expect(resp.address.toString()).toEqual(expected_address)
      expect(resp.pubkey.toString()).toEqual(expected_pubkey)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address - reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        rejectKeyword: isTouchDevice(m.name) ? 'QR' : '',
      })
      const app = new NamadaApp(sim.getTransport())

      const respRequest = app.showAddressAndPubKey(hdpath)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_reject`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.returnCode).toEqual(0x6986)
      expect(resp.errorMessage).toEqual('Transaction rejected')
    } finally {
      await sim.close()
    }
  })

})
