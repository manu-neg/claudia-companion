"""Extra MCP tool groups, each a module with its own `register(server, client)`.

`questions`: ask the owner a choice question, wait for the answer, cancel
it, send done/failed alerts (ADR 0021). `folders`: one level of folders
(ADR 0027). `progress`: live work trackers in one call (ADR 0029). The
publishing tools live in `interfaces/mcp/server.py`.
"""
