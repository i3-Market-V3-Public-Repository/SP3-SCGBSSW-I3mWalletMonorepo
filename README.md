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

# Documentation

The complete documentation can be found [here](https://i3-market.gitlab.io/code/backplane/backplane-api-gateway/backplane-api-specification/systems/trust-security-privacy/smart-wallet/overview.html).
