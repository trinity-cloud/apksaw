# Contributing

## Setup

```bash
git clone https://github.com/trinity-cloud/apksaw
cd apksaw
uv sync --all-extras
```

## Running Tests

```bash
uv run pytest
```

## Adding a New Tool

1. Choose the appropriate module in `src/apksaw/tools/` or create a new one.
2. Decorate your function with `@mcp.tool()` from `apksaw.server`.
3. Use Python type hints — FastMCP generates the MCP schema from them.
4. Write a clear docstring — it becomes the tool's description in the MCP schema.
5. Add a brief entry to the relevant page in `docs/tools/`.

Example:

```python
from apksaw.server import mcp
from apksaw.session import get_session

@mcp.tool()
def my_new_tool(session_id: str, some_param: str) -> dict:
    """Short description of what this tool does."""
    session = get_session(session_id)
    # implementation
    return {"result": ...}
```

## Adding a New Tool Module

If the new tools form a distinct category:

1. Create `src/apksaw/tools/mymodule.py`.
2. Import it in `src/apksaw/server.py` alongside the existing imports.
3. Add it to the `nav` in `mkdocs.yml` and create `docs/tools/mymodule.md`.

## Code Style

- Format with `ruff format`.
- Lint with `ruff check`.
- All tools must return a JSON-serializable dict or list.
- Never block the event loop — use `asyncio.to_thread` for heavy work if needed.

## Pull Requests

- Keep PRs focused on one feature or fix.
- Include a test if you're adding analysis logic.
- Update relevant docs pages.
