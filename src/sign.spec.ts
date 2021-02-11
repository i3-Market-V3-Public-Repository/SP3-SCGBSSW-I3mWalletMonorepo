describe('testing function sign(\'hello\')', function () {
  const regex = /^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/
  it(`should return a JWS string matching ${regex.toString()}`, async function () {
    const ret = await _pkg.sign('hello')
    chai.expect(ret).to.match(regex)
  })
})

describe('testing function sign(new Uint8Array(16))', function () {
  const regex = /^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/
  it(`should return a JWS string matching ${regex.toString()}`, async function () {
    const ret = await _pkg.sign(new Uint8Array(16))
    chai.expect(ret).to.match(regex)
  })
})
