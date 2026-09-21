#!/usr/bin/env bash
# What a registry already holds for the version being released. Sourced, never executed.
#
# A release publishes to three registries that cannot be updated together, and none of
# them lets a version be replaced. So every publish step first classifies its target, and
# the whole workflow becomes safe to re-run after a partial failure: recovery is "re-run
# the failed jobs", which ships the same verified bytes.
#
#   ABSENT     nothing there                 -> publish
#   PARTIAL    some of our files, all equal  -> publish the rest (PyPI only: many wheels)
#   SAME       exactly our bytes             -> nothing to do; succeed
#   DIFFERENT  other bytes under our version -> stop. It cannot be replaced, and carrying
#                                               on would leave registries disagreeing about
#                                               what this version is. Cut a new version.
#
# shellcheck disable=SC2034  # constants for the scripts that source this file
readonly STATE_ABSENT=ABSENT
readonly STATE_PARTIAL=PARTIAL
readonly STATE_SAME=SAME
readonly STATE_DIFFERENT=DIFFERENT
