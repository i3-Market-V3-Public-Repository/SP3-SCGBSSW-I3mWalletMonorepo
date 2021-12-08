import { expect } from 'chai'

describe('parseHex', function () {
  const vectors = [
    {
      input: '0x234FE67',
      output: '234fe67'
    },
    {
      input: '234FE67',
      output: '234fe67'
    }
  ]
  for (const vector of vectors) {
    it(`parseHex${vector.input} should return ${vector.output}`, function () {
      const ret = _pkg.parseHex(vector.input)
      expect(ret).to.equal(vector.output)
    })
  }
  it('parseHex(\'adge3\') should throw error', function () {
    expect(() => {
      _pkg.parseHex('adge3')
    }).to.throw(RangeError)
  })
})
