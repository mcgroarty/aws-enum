# Pre-commit Hooks Documentation

This repository includes comprehensive pre-commit hooks to ensure code quality and consistency.

## What Gets Checked

### Python Validation
- **Syntax checking**: Validates Python syntax using `py_compile`
- **Code quality**: Runs `flake8` linting (if available)
- **Formatting**: Optional `black` formatting (via pre-commit framework)

### Markdown Validation
- **Linting**: Runs `markdownlint` with project-specific configuration
- **Consistent formatting**: Ensures markdown follows best practices
- **Configuration**: See `.markdownlint.yaml` for specific rules

### General File Checks (pre-commit framework only)
- End-of-file fixing
- Trailing whitespace removal
- Large file detection
- Merge conflict detection
- Case conflict detection

## Installation Options

### Option 1: Quick Setup (Recommended)
```bash
./scripts/install-hooks.sh
```

This script automatically detects your environment and installs the appropriate hooks.

### Option 2: Manual Pre-commit Framework Setup
```bash
pip install pre-commit
pre-commit install
```

### Option 3: Simple Hook Only
```bash
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Dependencies

### Required for Full Validation
```bash
# Python tools
pip install flake8 black pre-commit

# Markdown tools (requires Node.js)
npm install -g markdownlint-cli
```

### Minimal Setup
The hooks work with basic Python installation but will skip optional checks if dependencies are missing.

## Configuration Files

- `.pre-commit-config.yaml`: Pre-commit framework configuration
- `.markdownlint.yaml`: Markdown linting rules
- `scripts/pre-commit-hook.sh`: Standalone hook script
- `scripts/install-hooks.sh`: Automated installation script

## Running Checks Manually

```bash
# All hooks (pre-commit framework)
pre-commit run --all-files

# Individual checks
python3 -m py_compile enumerate-elbs.py
flake8 enumerate-elbs.py
markdownlint README.md

# Test hook script directly
./scripts/pre-commit-hook.sh
```

## Troubleshooting

**Hook not running**: Ensure hooks are installed with `./scripts/install-hooks.sh`

**Missing dependencies**: Install optional dependencies or hooks will skip those checks

**Commit blocked**: Fix the reported issues and commit again

**Update hooks**: `pre-commit autoupdate` (framework only)