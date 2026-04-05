#!/bin/bash
set -e

cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cp build/compile_commands.json .
