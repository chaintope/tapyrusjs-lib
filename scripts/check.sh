#!/bin/sh
# ビルド・lint・ユニットテストをまとめて実行する。
# いずれかが失敗した時点で終了する。
set -e

npm run build
npm run lint
npm run unit
