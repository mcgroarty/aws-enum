#!/bin/bash

# Simple pre-commit hook for development environments without pre-commit framework
# This script validates Python syntax and runs basic markdown checks

set -e

echo "🔍 Running pre-commit checks..."

# Check Python syntax
echo "  ✓ Checking Python syntax..."
python3 -m py_compile enumerate-elbs.py || {
    echo "  ❌ Python syntax error in enumerate-elbs.py"
    exit 1
}

# Check for basic Python issues
echo "  ✓ Checking for basic Python issues..."
python3 -m flake8 --max-line-length=88 --extend-ignore=E203,W503 enumerate-elbs.py || {
    echo "  ⚠️  flake8 warnings found (not blocking commit)"
}

# Check for common markdown issues if markdownlint is available
if command -v markdownlint >/dev/null 2>&1; then
    echo "  ✓ Checking markdown files..."
    markdownlint --config .markdownlint.yaml README.md || {
        echo "  ❌ Markdown linting failed"
        exit 1
    }
else
    echo "  ⚠️  markdownlint not found - skipping markdown checks"
    echo "     Install with: npm install -g markdownlint-cli"
fi

echo "✅ All pre-commit checks passed!"