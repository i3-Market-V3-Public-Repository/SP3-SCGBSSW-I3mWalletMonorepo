describe('testing function echo()', function () {
  const inputs = ['Hello!', 'Goodbye!']
  for (const input of inputs) {
    describe(`echo(${input})`, function () {
      it(`should return ${input}`, function () {
        const ret = _pkg.echo(input)
        chai.expect(ret).to.equal(input)
      })
    })
  }
})
