#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

TEST_FILE=
ARGS=()
PROG_ARGS=()

BYTEBOX="${SCRIPT_DIR}/../../zig-out/bin/${TEST_RUNTIME_EXE:-bytebox}"

while [[ $# -gt 0 ]]; do
    case $1 in
    --version)
        ${BYTEBOX} -v
        exit 0
        ;;
    --test-file)
        TEST_FILE="$2"
        shift
        shift
        ;;
    --arg)
        PROG_ARGS+=("$2")
        shift
        shift
        ;;
    --env)
        ARGS+=("--env" "$2")
        shift
        shift
        ;;
    --dir)
        ARGS+=("--dir" "$2")
        shift
        shift
        ;;
    *)
        echo "Unknown option $1"
        exit 1
        ;;
    esac
done

$BYTEBOX $TEST_FILE "${ARGS[@]}" "${PROG_ARGS[@]}"