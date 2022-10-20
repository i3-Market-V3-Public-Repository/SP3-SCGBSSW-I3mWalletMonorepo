# i3m-wallet-monorepo

A monorepo containing all the i3m packages

# Documentation

The complete documentation can be found [here](https://i3-market.gitlab.io/code/backplane/backplane-api-gateway/backplane-api-specification/systems/trust-security-privacy/smart-wallet/overview.html).

# Start

```bash
npm i

# for development of all packages
npm run install:dev

# for development of wallet:desktop
npm run install:desktop

# for development of libraries
npm run install:libs

npm start
```

# Publish

To publish the wallet libraries you can:

```bash
# Execute the libraries script. You have to set up the variable I3M_NPM_REGISTRY_AUTH
*scripts/libraries.sh*

# Or execute it on a container
docker-compose run libraries
```

To publish the wallet-desktop app:

```bash
# Execute the publish script. Your system must have the .env-template variables configured
*scripts/publish.sh*

# Or execute it on a container
docker-compose run publisher
```


