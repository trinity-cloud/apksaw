# Contributing to apksaw

Thank you for your interest in contributing. This document covers everything you need to get started.

## Getting started

1. Fork the repository and clone your fork:
   ```
   git clone https://github.com/<your-username>/apksaw.git
   cd apksaw
   ```

2. Create a feature branch:
   ```
   git checkout -b feature/my-new-tool
   ```

3. Install development dependencies with [uv](https://github.com/astral-sh/uv):
   ```
   uv sync --dev
   ```

4. Make your changes, write tests, and verify everything passes:
   ```
   uv run pytest tests/ -v
   uv run ruff check src/
   ```

5. Open a pull request against the `main` branch with a clear description of what you changed and why.

## Code style

apksaw uses [ruff](https://docs.astral.sh/ruff/) for linting. Run `uv run ruff check src/` before submitting. The project targets Python 3.10+ and uses standard library typing conventions (e.g. `list[str]` instead of `List[str]`).

## Adding a new tool

All MCP tools live in `src/apksaw/tools/`. Follow these steps to add one:

1. **Create (or extend) a module** — put logically related tools in the same file, e.g. `src/apksaw/tools/mytool.py`.

2. **Register the tool** — decorate your function with `@mcp.tool()`:
   ```python
   from apksaw.server import mcp
   from apksaw.session import get_session

   @mcp.tool()
   def my_new_tool(session_id: str, some_param: str = "") -> dict:
       """One-line summary.

       Longer description used by the AI agent to decide when to call this tool.

       Args:
           session_id: Session ID returned by load_apk.
           some_param: Description of the parameter.

       Returns:
           {"status": "ok", "data": {...}} or {"status": "error", "message": "..."}
       """
       session = get_session(session_id)
       # ... your logic ...
       return {"status": "ok", "data": {}}
   ```

3. **Import the module in `server.py`** so the tool is registered at startup:
   ```python
   from .tools import mytool  # noqa: F401, E402
   ```

4. **Write tests** in `tests/test_mytool.py`. Use the `mock_session` fixture from `tests/conftest.py` and mock `get_session` to avoid needing a real APK:
   ```python
   from unittest.mock import patch

   def test_my_new_tool_success(mock_session):
       with patch("apksaw.tools.mytool.get_session", return_value=mock_session):
           from apksaw.tools.mytool import my_new_tool
           result = my_new_tool(mock_session.session_id)
       assert result["status"] == "ok"
   ```

## Commit messages

Keep the subject line under 72 characters and use the imperative mood ("Add tool", not "Added tool"). Reference any relevant issue numbers.

## Questions

Open a [GitHub Discussion](https://github.com/trinity-cloud/apksaw/discussions) or file an issue if you are unsure where something belongs.
