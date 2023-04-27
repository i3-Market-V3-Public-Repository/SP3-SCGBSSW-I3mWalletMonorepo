/* eslint-disable @typescript-eslint/no-unused-expressions */

import { passwordCheck, PasswordStrengthOptions, VaultError } from '#pkg'
import { expect } from 'chai'

interface Test {
  password: string
  passwordStrengthOptions?: PasswordStrengthOptions
}

describe('Password check', function () {
  const testsToPass: Test[] = [
    {
      password: 'esmuylargaMuyLargaPeroSinSimbolosNiNumeros',
      passwordStrengthOptions: {
        numbers: false,
        symbols: false
      }
    },
    {
      password: '00esmuylargaMuyLargaPeroSinSimbolos',
      passwordStrengthOptions: {
        symbols: false
      }
    },
    {
      password: '124&%Short',
      passwordStrengthOptions: {
        minLength: 10
      }
    }
  ]
  const testsToFail: Test[] = [
    {
      password: '00esmuylargaMuyLargaPeroSinSimbolos'
    },
    {
      password: '124&%Short',
      passwordStrengthOptions: {
        minLength: 12
      }
    }
  ]

  for (const test of testsToPass) {
    const defaultOptions = test.passwordStrengthOptions === undefined
    it(`Password ${test.password} is valid for ${defaultOptions ? 'the default options' : JSON.stringify(test.passwordStrengthOptions)}`, function () {
      let err = false
      try {
        passwordCheck(test.password, test.passwordStrengthOptions)
      } catch (error) {
        console.log((error as VaultError).data)
        err = true
      }
      expect(err).to.be.false
    })
  }

  for (const test of testsToFail) {
    const defaultOptions = test.passwordStrengthOptions === undefined
    it(`Password ${test.password} is invalid for ${defaultOptions ? 'the default options' : JSON.stringify(test.passwordStrengthOptions)}`, function () {
      let err = false
      try {
        passwordCheck(test.password, test.passwordStrengthOptions)
      } catch (error) {
        console.log((error as VaultError).data)
        err = true
      }
      expect(err).to.be.true
    })
  }
})
