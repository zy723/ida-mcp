"""Ported ida-pro-mcp runtime sources, shipped as data.

Nothing in this package is imported by the server process. bootstrap.py
reads these files with importlib.resources and execs them into a remote
worker's shared namespace (``_ida_mcp_pro_<sha16>``); the modules exist on
disk only so the exact runtime source ships inside the wheel.

See NOTICE for attribution (ida-pro-mcp MIT, ida-sigmaker MIT).
"""