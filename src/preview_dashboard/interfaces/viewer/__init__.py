"""Viewer interface: the owner-facing dashboard and preview ASGI apps.

Built by `app_factory.build_dashboard_app` / `build_preview_app` from small,
separately tested security components (identity, CSRF, headers, fetch
metadata, limits) around route modules in `routes/`. See docs/security.md.
"""
