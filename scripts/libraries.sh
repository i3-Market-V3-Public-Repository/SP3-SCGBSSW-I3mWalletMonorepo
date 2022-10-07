# Another solution is to use: npx lerna exec --scope "@i3m/*" --no-bail -- npm publish --access public
# The problem is that it doesn't manage the errors properly

REPO_FOLDER=$PWD
ERROR=0

publish() {
  cd $1
  npm publish --access public || ERROR=1
  cd $REPO_FOLDER
}

# Prepare
if [ -d ./node_modules ]; then
  echo Node modules already exists
else
  npm ci
fi

# Publish packages
publish packages/wallet-protocol
publish packages/wallet-protocol-api
publish packages/wallet-protocol-utils
publish packages/wallet-desktop-openapi
publish packages/base-wallet
publish packages/sw-wallet
publish packages/bok-wallet
publish packages/server-wallet
exit $ERROR
