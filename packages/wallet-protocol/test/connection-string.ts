import * as _pkg from '#pkg'
const { constants, ConnectionString } = _pkg

describe('ConnectionString', function () {
  let connString: _pkg.ConnectionString
  const portOffset = 12

  before(async () => {
    connString = await ConnectionString.generate(constants.INITIAL_PORT as number + portOffset, constants.DEFAULT_RANDOM_LENGTH)
  })

  it('should return the proper port', async function () {
    chai.expect(connString.extractPort()).to.equal(constants.INITIAL_PORT as number + portOffset)
  })

  it('should converted to string properly', async function () {
    const pin = connString.toString()
    const newConnString = ConnectionString.fromString(pin, constants.DEFAULT_RANDOM_LENGTH)
    chai.expect(connString.extractPort()).to.equal(newConnString.extractPort())
  })
})
