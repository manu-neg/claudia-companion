"""Shared wire protocols between processes (framework-free: stdlib + domain only).

`notifier` is the JSON format of the admin API's `/v1/notifier/*` routes,
imported by the admin routes, the notifier's `AdminDeliveryQueue` adapter
and the notifier process (ADR 0021).
"""
