# Instructions:
# Download this file (you don't need anything else)
# Build: docker build -t wcv . 
# Generate keys if you don't have a valid pair : 
#  - [new keys] docker run -it --init wcv generateJwks ES256
#  - [using a privatekey in hex] docker run -it --init wcv generateJwks ES256 8c2ebb279f950edec15d36f3d7b10a35858d9743f964489ec0ad8860e3e9423b
# Copy template.env to .env and fill all the required env variables.
# Run the Wallet Cloud-Vault: docker run -it --init -p 127.0.0.1:3000:3000 --env-file .env wcv
FROM node:18-alpine

# VERSION can be used to build docker with a specific NPM version of the @i3m/conflict-resolver-service
ARG VERSION=${VERSION:-latest}

ENV NODE_ENV=${NODE_ENV:-production}

ENV CORS_ACCESS_CONTROL_ALLOW_ORIGIN=${CORS_ACCESS_CONTROL_ALLOW_ORIGIN:-*}

WORKDIR /app

RUN chown node.node /app &&\
    apk update &&\
    apk upgrade

USER node

RUN mkdir .keys && \
    npm install @i3m/wallet-cloud-vault@${VERSION}

EXPOSE 3000

ENTRYPOINT [ "npx" ]

CMD [ "wcv" ]
