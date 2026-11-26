#!/bin/sh
# Builds and runs the platform-independent unit tests and the 100-sample
# acceptance harness with the native (Linux/macOS) toolchain. The production
# Windows build is driven by the top-level CMakeLists.txt instead.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${ROOT}/whitelist/tests/build"
mkdir -p "${BUILD}"

CORE_SRCS="
  whitelist/hh_types.cpp
  whitelist/hh_classifier.cpp
  whitelist/hh_whitelist.cpp
  whitelist/hh_json.cpp
  whitelist/hh_report_adapter.cpp
  whitelist/hh_postprocessor.cpp
  whitelist/hh_output.cpp
"

echo "[*] Building unit tests..."
c++ -std=c++17 -Wall -Wextra -I"${ROOT}" \
    whitelist/tests/unit_tests.cpp ${CORE_SRCS} \
    -o "${BUILD}/unit_tests"

echo "[*] Building 100-sample acceptance harness..."
c++ -std=c++17 -Wall -Wextra -I"${ROOT}" \
    whitelist/tests/acceptance_harness.cpp ${CORE_SRCS} \
    -o "${BUILD}/acceptance"

echo
"${BUILD}/unit_tests"
echo
"${BUILD}/acceptance"
