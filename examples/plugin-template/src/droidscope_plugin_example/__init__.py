"""Example apksaw plugin that adds a custom analysis tool."""


def register(ctx):
    """Called by apksaw plugin system on startup."""

    @ctx.register_tool
    def example_scan(session_id: str) -> dict:
        """Example plugin tool that performs a custom scan."""
        session = ctx.get_session(session_id)
        # Custom analysis logic here
        return {"status": "ok", "data": {"message": "Plugin tool executed"}}
