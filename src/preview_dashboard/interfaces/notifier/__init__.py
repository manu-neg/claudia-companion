"""The notifier process (ADR 0021): run loop and CLI command functions.

`runner` drives `DeliveryService`; `commands` holds `serve_notifier`,
`pair` and `send_test`, wired into `interfaces/cli.py`. The JSON format of
`/v1/notifier/*` lives in `preview_dashboard.wire.notifier` (shared with
the admin side and `adapters/admin_queue.py`).
"""
