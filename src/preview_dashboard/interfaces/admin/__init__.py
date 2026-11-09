"""Admin interface: the bearer-token API served on a local Unix socket.

`app.build_admin_app` builds the ASGI app (item routes in `api.py`,
question/alert routes in `questions_api.py`, notifier routes in
`notifier_api.py`, long-poll caps in `longpoll.py`, token scopes and peer
checks in `auth.py`, errors/logging in `errors.py`, streaming multipart
intake in `multipart.py`); `server.py` binds the socket and runs uvicorn.
Clients: the MCP server and root CLI (admin token), the notifier
(`/v1/notifier/*` only, notifier token). ADR 0003, 0021, 0022; docs/api.md.
"""
