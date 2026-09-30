#!/bin/sh
# ビルド・フォーマット検査・lint・ユニットテストをまとめて実行する。
# いずれかが失敗した時点で終了する。
#
# 検証内容は CI（.github/workflows/ci.yml）と同じである。
# `npm test` は build、format:ci、lint、カバレッジ閾値付きのユニットテストを実行する。
# テストコードの lint は `npm test` に含まれないため別に実行する。
set -e

npm test
npm run lint:tests
