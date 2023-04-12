# Docker

## Production

Download this file (you don't need anything else)
Build: `docker build -t cvs .`
Copy `.env.template` to `.env` and fill all the required env variables.

Run the Cloud-Vault Server: `docker run -it --init -p 127.0.0.1:3000:3000 --env-file .env cvs`

## Development

A docker compose has been created for development that includes the service in the i3m backplane

> It is necessary to empty volumes before running again, so do not forget to empty them before rebuilding

```console
docker compose down -v
docker compose up -d
```
