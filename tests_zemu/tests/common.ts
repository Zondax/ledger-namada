import { DEFAULT_START_OPTIONS, IDeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')
const APP_PATH_ST = Resolve('../app/output/app_stax.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

type ExpectedValues = {
    publicAddress: string,
    ak: string,
    nsk: string,
    viewKey: string,
    ivk: string,
    ovk: string
}

export const expectedKeys: ExpectedValues = {
    publicAddress: "4a223af299fe6aca27f654fefa20c4671bab75ccaef67c1d6589d76d31e7b9e4",
    ak: "8ae9cead595170d442eea33e2dd4580992dcf670f37abd190ef48836bccfdcaa",
    nsk: "833c4f67b2edbef6427294c75fb89b14433e7682c050430b25bdff85aa7dfd05",
    viewKey: "8ae9cead595170d442eea33e2dd4580992dcf670f37abd190ef48836bccfdcaac718ce1ecfa425837ed04d1188eccc608547af4428362dde979a523f9d3a49c1",
    ivk: "d07d8f566795302a955408375789881e6b356f9b90e1e408113130b79dd7e80d",
    ovk: "c0a2ca3bdc4133ff484db3d13033a284514d87bb82a9bf19e6579464b5c13007"
}

export const hdpath = `m/44'/877'/0'/0'/0'`

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}
