#!/bin/bash

# Install pre-commit hooks for the aws-enumerate-elbs repository

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "🔧 Installing pre-commit hooks..."

# Method 1: Install pre-commit framework (recommended)
if command -v pre-commit >/dev/null 2>&1; then
    echo "  ✓ Found pre-commit framework, installing hooks..."
    cd "$REPO_ROOT"
    pre-commit install
    echo "  ✅ Pre-commit framework hooks installed!"
    echo ""
    echo "  To run all hooks manually: pre-commit run --all-files"
    echo "  To update hooks: pre-commit autoupdate"
    
else
    # Method 2: Use simple shell script fallback
    echo "  ⚠️  pre-commit framework not found"
    echo "     Install with: pip install pre-commit"
    echo ""
    echo "  📄 Installing simple pre-commit hook as fallback..."
    
    cp "$REPO_ROOT/scripts/pre-commit-hook.sh" "$HOOKS_DIR/pre-commit"
    chmod +x "$HOOKS_DIR/pre-commit"
    echo "  ✅ Simple pre-commit hook installed!"
fi

echo ""
echo "📋 Additional setup recommendations:"
echo "   • Install flake8: pip install flake8"
echo "   • Install markdownlint: npm install -g markdownlint-cli"
echo "   • Install black (optional): pip install black"
echo ""
echo "🎉 Pre-commit setup complete!"