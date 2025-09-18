export { generateHOTP } from './src/generateHOTP'
export { generateSecret } from './src/generateSecret'
export { generateTOTP } from './src/generateTOTP'
export { validate } from './src/validate'

export type {
  HOTPOptions,
  HmacAlgorithm,
  TOTPOptions,
  TOTPValidateOptions
} from './src/types'