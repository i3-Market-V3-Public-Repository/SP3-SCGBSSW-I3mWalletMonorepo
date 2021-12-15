import { hashable } from 'object-sha'

describe('Class NrError', function () {
  let nrError1, nrError2
  it('should accumulate NR error msgs when one nrError is used to instance another one', function () {
    nrError1 = new _pkg.NrError(new Error('error'), ['invalid dispute request'])
    nrError2 = new _pkg.NrError(nrError1, ['invalid format', 'invalid poo'])
    const nrErrors: _pkg.NrError['nrErrors'] = ['invalid dispute request', 'invalid format', 'invalid poo']
    chai.expect(hashable(nrError2.nrErrors)).to.equal(hashable(nrErrors))
  })
})
