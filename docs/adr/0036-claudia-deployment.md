# ADR 0036: Claudia deployment (unit M9)

**TL;DR:** `deploy/install.sh --claudia` installs the Claudia host and the weekly gardener as **root** units next to the dashboard, with one group per secret (`pdash-claudiatok`, `pdash-totp`) and a dedicated knowledge-base read group `pdash-kb` held only by the viewer. Installed ≠ enabled: only the owner's `claudia_enabled = true` (and a TOTP secret) starts it.

## Context
- The host runs `claude -p --resume` on the owner's **root** subscription login (D3, D15) and may dispatch work anywhere under `/root` (D14). It cannot be sandboxed like the dashboard services without breaking that work.
- The host loads `claudia.token` with `TokenLoader(own=CLAUDIA)`: as plain root (egid 0) it would refuse a `root:pdash-claudiatok` file (C45/C12).
- The viewer must read the KB (C57) but `pdash-viewer` has no private group (its primary group is the shared `pdash`, ADR 0013), so the backlog's `root:pdash-viewer` KB owner does not exist.
- Voice models (D13) are 60–110 MB each; no checksums were recorded in the V6 spike.

## Decision
1. **Units.** `claudia-host.service`: `User=root`, `Group=pdash-claudiatok` (egid = the token's group, the one non-root group trusted for a process's own token), `UnsetEnvironment=` of the four C49 variables, `Restart=on-failure`, `KillMode=control-group` (C58), `python -I -m …` (no cwd imports), only kernel-facing hardening. `claudia-gardener.service` (+ weekly `.timer`, C54): root without capabilities, `Group=pdash-kb` + `SupplementaryGroups=pdash` (admin socket), `ProtectSystem=strict`, writes only the KB and `~/.claude`.
2. **Groups.** `pdash-claudiatok` and `pdash-totp` have `pdash-admin` as their only member (S-C1 S2). `pdash-kb` has **no** members; the viewer unit gets it via `SupplementaryGroups=`, so the admin and purge (group `pdash`) never read the KB. It is created on every host because the static viewer unit needs it to start.
3. **Viewer confinement.** `ReadOnlyPaths=-/var/lib/claudia-kb`; `InaccessiblePaths=` the admin-only Claudia DB dir, voice store, step-up state, host state, `totp.secret`, `claudia.token` (all `-`-prefixed: absent on hosts without Claudia).
4. **Admin args** come from an optional `claudia-admin.env` (`--claudia-peer-uid 0 --token-group claudia=… --token-group totp=…`), unbraced like the notifier's (ADR 0023).
5. **Off by default, host state decides.** The installed host unit keeps Claudia installed on re-runs; it is enabled only when `claudia_enabled = true` (read, never written) and started only when `totp.secret` exists (also a unit `ConditionPathExists`). `--claudia` without the notifier is refused.
6. **Voice:** no downloads. `--voice-models DIR` copies models only if all four files match SHA-256 lines pinned in `deploy/claudia/voices.sha256` (shipped empty → refused); voice off otherwise.

7. **Amendment (F-C2a-3, S-C2a review).** (a) Dirs inside the admin-owned data dir are made and fixed by `pdash-admin` itself (`runuser … mkdir/chgrp/chmod`), then a no-follow `stat` must match; a symlink/non-dir is refused — root never runs `install -d` there (it follows symlinks on existing dirs). (b) Gardener masks the data dir, host state and every non-admin secret; host masks `totp.secret`/`notifier.token`/`telegram.token` (advisory). (c) `voice/` is pre-created before the viewer restarts; check.sh proves each viewer mask with `findmnt --task` and the KB's ro mount with `findmnt -T`; file masks lost to renames are covered by modes + a documented viewer restart (`stepup-state.json` moved into `claudia/` in F-C2b-3: covered by that mask, mode check kept). (d) install.sh refuses inside `claudia-host.service`'s cgroup. (e) Reused Claudia groups with unexpected members (incl. primary-group users) are refused; check.sh checks exact membership. (f) Voice copies are hashed in a root-only staging dir, and installed copies re-verified every run. (g) The voice extra gets upper bounds and its own CI pip-audit (locked `uv export`).

## Consequences
- The host is the least confined process on the box (documented in operations + security Known limitations); its controls are the host's own checks (C49–C52, C59/C60).
- Files her runs create are group `pdash-claudiatok` (umask 0022: no new exposure beyond world-readable).
- Voice needs one manual commit of the real hashes before `--voice-models` works.
- `systemd-analyze security` (≤ 2.0) is not applied to the two Claudia units.
- Addendum (F-CL7): the viewer already reads the original KB (no copy); host rule 8 and the recap now make her record discussed topics there, and the host keeps a read-only `guide.md` reference in the KB root.
