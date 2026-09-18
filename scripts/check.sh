#!/bin/sh
# ビルド・lint・ユニットテストをまとめて実行する。
# いずれかが失敗した時点で終了する。
#
# 検証内容は CI（.github/workflows/ci.yml）と同じ lint + unit に揃えている。
# `npm run unit` は内部で build を走らせるため、ここでは build 済みの
# `nobuild:unit` を呼ぶ。
#
# `npm test` が実行する format:ci と lint:tests は含めていない。
# ts_src/metadata.ts と test/metadata.spec.ts が master の時点で
# この 2 つに失敗するためである。解消後にここへ追加する。
set -e

npm run build
npm run lint
npm run nobuild:unit
