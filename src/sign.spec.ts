describe('testing function sign(\'hello\')', function () {
  const regex = /^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/
  it(`should return a JWS string matching ${regex.toString()}`, async function () {
    const ret = await _pkg.sign('hello')
    chai.expect(ret).to.match(regex)
  })
})
