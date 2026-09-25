#!/usr/bin/env bash
# What a registry already holds for the version being released. Sourced, never executed.
# Lets every publish step re-run safely after a partial failure.
#
#   ABSENT     nothing there                 -> publish
#   PARTIAL    some of our files, all equal  -> publish the rest (PyPI only)
#   SAME       exactly our bytes             -> succeed
#   DIFFERENT  other bytes under our version -> fail; cut a new version
#
# shellcheck disable=SC2034  # constants for the scripts that source this file
readonly STATE_ABSENT=ABSENT
readonly STATE_PARTIAL=PARTIAL
readonly STATE_SAME=SAME
readonly STATE_DIFFERENT=DIFFERENT
