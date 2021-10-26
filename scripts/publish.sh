#!/bin/sh

# DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
DIR=$(dirname "$0")
ROOT_DIR="$DIR/.."
LOG_FILE=$ROOT_DIR/publish.log
VERSION="$( jq -r '.version' $ROOT_DIR/package.json )"

echo Initialize logs at $LOG_FILE
rm -rf $LOG_FILE

# UPLOAD DEB
UPLOAD_PATH="$(find $ROOT_DIR/packages/wallet-desktop/release/ -name *.deb)"
if  [[ ! -z "$UPLOAD_PATH" ]]; then
  DEB_FILE=${UPLOAD_PATH##*/}
  echo Publishing deb file: $DEB_FILE
  curl -v --user $NEXUS_USER:$NEXUS_PASSWD --upload-file $UPLOAD_PATH $NEXUS_HOST/repository/i3m-raw/i3m-wallet/$VERSION/linux/$DEB_FILE 2>> $LOG_FILE
fi

# UPLOAD APP IMAGE
UPLOAD_PATH="$(find $ROOT_DIR/packages/wallet-desktop/release/ -name *.AppImage)"
if  [[ ! -z "$UPLOAD_PATH" ]]; then
  UPLOAD_FILE=${UPLOAD_PATH##*/}
  echo Publishing AppImage file: $UPLOAD_FILE
  curl -v --user $NEXUS_USER:$NEXUS_PASSWD --upload-file $UPLOAD_PATH $NEXUS_HOST/repository/i3m-raw/i3m-wallet/$VERSION/linux/$UPLOAD_FILE 2>> $LOG_FILE
fi

# UPLOAD DMG
UPLOAD_PATH="$(find $ROOT_DIR/packages/wallet-desktop/release/ -name *.dmg)"
if  [[ ! -z "$UPLOAD_PATH" ]]; then
  UPLOAD_FILE=${UPLOAD_PATH##*/}
  echo Publishing dmg file: $UPLOAD_FILE
  curl -v --user $NEXUS_USER:$NEXUS_PASSWD --upload-file $UPLOAD_PATH $NEXUS_HOST/repository/i3m-raw/i3m-wallet/$VERSION/mac/$UPLOAD_FILE 2>> $LOG_FILE
fi

# UPLOAD RAR
UPLOAD_PATH="$(find $ROOT_DIR/packages/wallet-desktop/release/ -name *.rar)"
if  [[ ! -z "$UPLOAD_PATH" ]]; then
  UPLOAD_FILE=${UPLOAD_PATH##*/}
  echo Publishing rar file: $UPLOAD_FILE
  curl -v --user $NEXUS_USER:$NEXUS_PASSWD --upload-file $UPLOAD_PATH $NEXUS_HOST/repository/i3m-raw/i3m-wallet/$VERSION/win/$UPLOAD_FILE 2>> $LOG_FILE
fi
