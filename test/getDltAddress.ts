import * as _pkg from '#pkg'

describe('parseHex', function () {
  const vectors = [
    {
      input: 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
      output: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903'
    },
    {
      input: '0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
      output: '0x17bd12C2134AfC1f6E9302a532eFE30C19B9E903'
    }
  ]
  for (const vector of vectors) {
    it(`getDltAddress('${vector.input}') should return '${vector.output}'`, function () {
      const ret = _pkg.getDltAddress(vector.input)
      chai.expect(ret).to.equal(vector.output)
    })
  }
  it('getDltAddress(\'adge3\') should throw error', function () {
    chai.expect(() => {
      _pkg.getDltAddress('adge3')
    }).to.throw(_pkg.NrError)
  })
})
