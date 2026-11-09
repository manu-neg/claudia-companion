# ADR 0024: Per-file trusted groups for token files

**TL;DR:** Each token file a process loads has its own trusted groups: root always; the process's own group only for its own token; `--token-group KIND=GROUP` only for that file; plain `--token-group GROUP` (unchanged, what deploy passes) for any file, but no two token files of one process may share a non-root group. A token readable by another process's group is refused. Fixes S-B L1.

## Context

- Three token files (C12, C36): `admin.token` (`root:pdash`, admin + root clients), `notifier.token` (`root:pdash-notifytok`, shared by admin and notifier), `telegram.token` (`root:pdash-notify`, notifier only).
- Until now one trusted set per process applied to every file it loaded: root + egid + all `--token-group`s. The admin (`--token-group pdash --token-group pdash-notifytok`) would accept `admin.token` in `pdash-notifytok` (readable by the notifier); the notifier would accept `telegram.token` in `pdash-notifytok` (readable by the admin).
- Deploy already passes plain `--token-group` flags; the flag must stay compatible. No code hardcodes group names (ADR 0017 G).

## Decision

- `interfaces/token_file.py`: `TokenKind` (admin, notifier, telegram), `TokenGroupPolicy(own, scoped, shared, egid)` and `TokenLoader` (one per process). `gids_for(kind)` = root + scoped[kind] + (shared − groups scoped to other files) + egid if `kind == own`; the egid is removed from every other file.
- `TokenLoader.load` refuses a file whose non-root group already owns another token file loaded by the same process ("each token needs its own group"). A group scoped to two files is refused at startup.
- `own`: admin for `serve-admin`, `check-config`, `question wait`, `notify test`; telegram for `serve-notifier`, `notify pair`. The shared `notifier.token` is never a service's own group.
- CLI: `--token-group [KIND=]GROUP`. Plain values keep working; `KIND=` binds a group to exactly one file (preferred for new deploys).
- `load_admin_token` (single-file) is unchanged for the MCP client and `gen-token`.

## Consequences

- Deployed layouts keep loading with the existing flags; swapped or merged groups now fail closed at startup, naming the file and the rule (never a token).
- Residual with plain flags: a process that loads only one token (admin with notifications off) can't compare groups; `--token-group notifier=pdash-notifytok` closes that too.
- Tests run as root (egid 0) where "own group" is root anyway; policy tests pass `egid` explicitly.
