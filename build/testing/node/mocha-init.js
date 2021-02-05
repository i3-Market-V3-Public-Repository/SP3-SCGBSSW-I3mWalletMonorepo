before(function () {
  // Just in case our module had been modified. Reload it when the tests are repeated (for mocha watch mode).
  delete require.cache[require.resolve('~root')]
  global._pkg = require('~root')
})
