# Instructions:
# Download this file (you don't need anything else)
# Build: docker build -t cvs . 
# Copy .env.template to .env and fill all the required env variables.
# Run the Cloud-Vault Server: docker run -it --init -p 127.0.0.1:3000:3000 --env-file .env cvs
FROM node:18-alpine

# VERSION can be used to build docker with a specific NPM version of the @i3m/cloud-vault-server
ARG VERSION=${VERSION:-latest}

WORKDIR /app

RUN chown node.node /app &&\
    apk update &&\
    apk upgrade

USER node

RUN npm install @i3m/cloud-vault-server@${VERSION}

EXPOSE 3000

ENTRYPOINT [ "npx" ]

CMD [ "cvs" ]
