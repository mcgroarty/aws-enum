#!/bin/bash

# Simple pre-commit hook for development environments without pre-commit framework
# This script validates Python syntax and runs basic markdown checks

set -e

echo "🔍 Running pre-commit checks..."

# Check Python syntax
echo "  ✓ Checking Python syntax..."
for py_file in *.py; do
    if [ -f "$py_file" ]; then
        python3 -m py_compile "$py_file" || {
            echo "  ❌ Python syntax error in $py_file"
            exit 1
        }
    fi
done

# Check for basic Python issues
echo "  ✓ Checking for basic Python issues..."
for py_file in *.py; do
    if [ -f "$py_file" ]; then
        python3 -m flake8 --max-line-length=88 --extend-ignore=E203,W503 "$py_file" || {
            echo "  ⚠️  flake8 warnings found in $py_file (not blocking commit)"
        }
    fi
done

# Check for common markdown issues if markdownlint is available
if command -v markdownlint >/dev/null 2>&1; then
    echo "  ✓ Checking markdown files..."
    for md_file in *.md *.markdown; do
        if [ -f "$md_file" ]; then
            markdownlint --config .markdownlint.yaml "$md_file" || {
                echo "  ❌ Markdown linting failed for $md_file"
                exit 1
            }
        fi
    done
else
    echo "  ⚠️  markdownlint not found - skipping markdown checks"
    echo "     Install with: npm install -g markdownlint-cli"
fi

echo "✅ All pre-commit checks passed!"
