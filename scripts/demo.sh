#!/usr/bin/env bash
# demo script. builds and runs tests.
# usage: ./scripts/demo.sh | tee demo_output.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"

echo "============================================================"
echo "  javelin linux demo"
echo "============================================================"
echo "date: $(date -Iseconds)"
echo "kernel: $(uname -r)"
echo "distro: $(source /etc/os-release && echo "$NAME $VERSION")"
echo "cpu: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo ""

echo "1. project structure"
tree -L 2 "$PROJECT_ROOT" 2>/dev/null || find "$PROJECT_ROOT" -maxdepth 2 -type d | sort

echo ""
echo "source files:"
find "$PROJECT_ROOT/src" -type f | sort

echo ""
echo "2. configure"
cd "$PROJECT_ROOT"
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DJVL_BUILD_TESTS=ON 2>&1

echo ""
echo "3. build"
cmake --build "$BUILD_DIR" --parallel "$(nproc)" 2>&1

echo ""
echo "4. unit tests"
cd "$BUILD_DIR"
./test_javelin

echo ""
echo "5. integration tests"
cd "$PROJECT_ROOT"
./tests/integration/test_full_pipeline.sh

echo ""
echo "6. benchmark"
cd "$BUILD_DIR"
if [[ -f ./memscan_benchmark ]]; then
    ./memscan_benchmark
else
    echo "(benchmark not built)"
fi

echo ""
echo "7. library exports"
cd "$BUILD_DIR"
nm -D libjavelin.so | grep ' T ' | awk '{print $3}' | sort

echo ""
echo "============================================================"
echo "  demo complete"
echo "============================================================"
