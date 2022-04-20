describe('parseHex', function () {
  const vectors = [
    {
      input: '0x234FE67',
      output: '234fe67'
    },
    {
      input: '234FE67',
      output: '234fe67'
    },
    {
      input: '0x123546146f23A',
      output: '123546146f23a'
    }
  ]
  for (const vector of vectors) {
    it(`parseHex('${vector.input}') should return '${vector.output}'`, function () {
      const ret = _pkg.parseHex(vector.input)
      chai.expect(ret).to.equal(vector.output)
    })
    it(`parseHex('${vector.input}', true) should return '0x${vector.output}'`, function () {
      const ret = _pkg.parseHex(vector.input, true)
      chai.expect(ret).to.equal('0x' + vector.output)
    })
  }
  it('parseHex(\'adge3\') should throw error', function () {
    chai.expect(() => {
      _pkg.parseHex('adge3')
    }).to.throw(_pkg.NrError)
  })
  it("parseHex('1287a3', undefined, 4) should return '001287a3'", function () {
    const ret = _pkg.parseHex('1287a3', undefined, 4)
    chai.expect(ret).to.equal('001287a3')
  })
  it('parseHex(\'1287542fe21\', true, 4) should throw error', function () {
    chai.expect(() => {
      _pkg.parseHex('1287542fe21', true, 4)
    }).to.throw(_pkg.NrError)
  })
})
