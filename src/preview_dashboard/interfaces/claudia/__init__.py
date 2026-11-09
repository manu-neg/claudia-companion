"""The Claudia host process (ADR 0031, unit M4b): entry point and host settings checks.

`main` starts the host (API-key refusal, token + socket checks, settings
check, poll/worker loops); `settings` verifies the host-owned Claude
settings file (C50) and every other settings source before each run (C59).
"""
