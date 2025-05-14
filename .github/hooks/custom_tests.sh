#!/bin/bash

echo "Detecting changed source files and matching test files..."

CHANGED_FILES=$(git diff --name-only origin/main...HEAD | grep '\.py$' || true)
TEST_FILES=""

for file in $CHANGED_FILES; do
  # Skip direct test file changes
  if [[ "$file" == _tests/* ]]; then
    TEST_FILES="$TEST_FILES $file"
    continue
  fi

  TEST_FILE=$(echo "$file" | sed 's/^src\//_tests\//' | sed 's/\.py$/_test.py/' | sed 's/\/\([^/]*\)_test\.py$/\/test_\1.py/')
  if [ -f "$TEST_FILE" ]; then
    TEST_FILES="$TEST_FILES $TEST_FILE"
  fi
done

if [ -n "$TEST_FILES" ]; then
  echo "Running only changed test files: $TEST_FILES"
  PYTHONPATH=src pytest -v $TEST_FILES
else
  echo "No matching test files to run."
fi
