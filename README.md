# i3m-wallet-monorepo

A monorepo containing all the i3m packages relaed to the i3-MARKET Wallet.

## Documentation

An overview documentation can be found [here](https://i3-market.gitlab.io/code/backplane/backplane-api-gateway/backplane-api-specification/systems/trust-security-privacy/smart-wallet/overview.html).

Or directly go the READMEs of the different packages ;-)

## Prepare the development environment

```bash
# Install root dependencies (lerna)
npm i

# for development of all packages
npm run install:dev

# for development of wallet:desktop
npm run install:desktop

# for development of libraries
npm run install:libs

# Starts the i3M wallet desktop application
npm start
```
