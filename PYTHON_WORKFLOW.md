# Python Development Workflow

This document outlines the canonical workflow for setting up new Python projects to ensure consistency across all development work.

## Standard Project Setup Workflow

Follow these steps in order when starting a new Python project:

### 1. Set Python Version
```bash
pyenv local <project-python>
```
- Sets the Python version for the specific project
- Creates a `.python-version` file in the project root
- Ensures consistent Python version across environments

### 2. Initialize Poetry Project
Choose one of the following based on your needs:

**For existing projects:**
```bash
poetry init
```
- Interactive initialization of `pyproject.toml`
- Allows you to specify project metadata and dependencies

**For new projects:**
```bash
poetry new <project-name>
```
- Creates a new project directory with standard structure
- Generates `pyproject.toml` and basic project layout

### 3. Add Dependencies
```bash
poetry add <package-name>
```
- Installs dependencies and adds them to `pyproject.toml`
- Poetry automatically creates and activates a `.venv` virtual environment
- Updates `poetry.lock` file with exact dependency versions

**Examples:**
```bash
poetry add requests
poetry add pytest --group dev
poetry add black --group dev
```

### 4. Run Commands
Use one of these approaches to execute commands in the project environment:

**Option A: Direct execution with poetry run**
```bash
poetry run python script.py
poetry run pytest
poetry run black .
```

**Option B: Activate shell environment**
```bash
poetry shell
# Now you're in the activated environment
python script.py
pytest
black .
```

## Benefits of This Workflow

- **Consistency**: Same approach across all projects
- **Isolation**: Each project has its own virtual environment
- **Reproducibility**: `poetry.lock` ensures exact dependency versions
- **Simplicity**: Poetry handles virtual environment creation and activation
- **Modern tooling**: Leverages current Python best practices

## Quick Reference

```bash
# Complete setup for new project
pyenv local 3.11.0
poetry init
poetry add requests pytest black --group dev
poetry shell

# Or for existing project
pyenv local 3.11.0
poetry install
poetry shell
```

---

*Follow this workflow consistently to maintain clean, reproducible Python development environments.*
