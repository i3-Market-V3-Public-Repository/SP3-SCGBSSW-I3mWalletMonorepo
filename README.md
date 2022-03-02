# i3m-wallet-monorepo

A monorepo containing all the i3m packages

# Start

First you need to add a configuration file with the api token for the GitLab repository.

```
@i3-market:registry=https://gitlab.com/api/v4/packages/npm/
'//gitlab.com/api/v4/packages/npm/:_authToken'="<YOUR_API_TOKEN>"
```

Then, to start the i3m-wallet execute commands:

```bash
npm i
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

# Documentation

The complete documentation can be found [here](https://i3-market.gitlab.io/code/backplane/backplane-api-gateway/backplane-api-specification/systems/trust-security-privacy/smart-wallet/overview.html).
