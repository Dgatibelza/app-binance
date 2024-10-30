/** ******************************************************************************
 *  (c) 2021-2023 Zondax AG
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
import { DEFAULT_START_OPTIONS, IDeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../build/nanos/bin/app.elf')
const APP_PATH_X = Resolve('../build/nanox/bin/app.elf')
const APP_PATH_SP = Resolve('../build/nanos2/bin/app.elf')
const APP_PATH_ST = Resolve('../build/stax/bin/app.elf')
const APP_PATH_FL = Resolve('../build/flex/bin/app.elf')

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

export const DEVICE_MODELS: { dev: IDeviceModel }[] = [
  { dev: { name: 'stax', prefix: 'ST', path: APP_PATH_ST } },
  { dev: { name: 'flex', prefix: 'FL', path: APP_PATH_FL } },
  { dev: { name: 'nanos', prefix: 'S', path: APP_PATH_S } },
  { dev: { name: 'nanox', prefix: 'X', path: APP_PATH_X } },
  { dev: { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP } },
]
