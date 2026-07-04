# Architecture

## Firewall mode

### Hook mode

Uses OCI hooks to apply per-container nftables rules inside the container's own
network namespace. Each container gets an isolated firewall. Works with pasta
(rootless default) and slirp4netns.

Lifecycle: `Shield.pre_start()` installs the OCI hook (idempotent), resolves DNS,
writes `profile.allowed`, pre-generates the complete nft ruleset to `ruleset.nft`,
and returns podman args with annotations. On each container start, the OCI hook
reads `state_dir` from annotations, applies the pre-generated `ruleset.nft` inside
the container's network namespace, and optionally starts a per-container *dnsmasq*
instance.  Gateway addresses are baked into the ruleset at generation time — no
runtime `/proc` discovery.

## Allowlisting

Allowlists are `.txt` files with one entry per line — domain names or raw
IP/CIDRs. Lines starting with `#` are comments.

Bundled defaults use domain names because they're stable across IP rotations and
easy to audit. DNS resolution uses the best available tier:

1. **dnsmasq** (preferred) — a per-container dnsmasq instance is started by the OCI
   hook with `nftset=` config entries (one per domain, targeting `allow_v4` and
   `allow_v6`), automatically populating the nft allow sets on every resolution at
   runtime. Handles IP rotation without manual intervention. Container DNS is
   redirected to the per-container dnsmasq (`127.0.0.1`, or a link-local address
   under krun) via a `resolv.conf` volume mount.
2. **dig** — pre-start `dig +short A/AAAA` resolution; IPs cached in `profile.allowed`
   with `st_mtime`-based freshness (default 1 hour).
3. **getent** — fallback when `dig` is also absent.

`detect_dns_tier()` selects the tier automatically based on available binaries,
dnsmasq compile-time nftset support, and whether an enforcing AppArmor profile
confines dnsmasq away from the state directory (see [AppArmor](apparmor.md)).

### Bundled profiles

| Profile | Contents |
|---------|----------|
| `base.txt` | OS repos (Ubuntu, Debian, Fedora, Alpine), NTP, OCSP/CRL |
| `dev-standard.txt` | GitHub, Docker Hub, PyPI, npm, crates.io, Go proxy, GitLab |
| `dev-python.txt` | PyPI, conda-forge, readthedocs |
| `dev-node.txt` | npm, Yarn, jsDelivr, unpkg |
| `nvidia-hpc.txt` | CUDA toolkit, NGC, NVIDIA repos |

Users can add custom profiles in `$XDG_CONFIG_HOME/terok/shield/profiles/`.

## Persistent deny

Operator deny decisions must survive `shield up` and container restarts.
The mechanism:

- `deny.list` — a per-container file in `state_dir`; every denied IP is
  appended here
- Denied IPs also go into dedicated nft deny sets (`deny_v4` / `deny_v6`),
  rejected and logged with the `DENIED` prefix; the deny sets are enforced
  even in bypass mode (`shield down`)
- On deny: remove from the allow set and `live.allowed`, add to the deny
  set, append to `deny.list`
- On allow: if the IP is in `deny.list`, remove it there and from the deny
  set (un-deny), then add to the allow set and `live.allowed`
- On reload (`shield_up`): compute effective allow IPs as
  `(profile.allowed ∪ live.allowed) − deny.list` and repopulate the deny
  sets from `deny.list`

Deny-list reconciliation happens in `state.py` (`StateBundle.read_effective_ips()`)
before ruleset generation; `nft/rules.py` receives a flat IP list with denied
entries already subtracted.

### IP normalization

`safe_ip()` normalizes all IPs to their canonical string form via
`ipaddress.ip_address()` / `ip_network()`. This ensures string comparisons
across state files are reliable regardless of input notation (e.g.
`2001:0db8::1` and `2001:db8::1` both normalize to `2001:db8::1`).

### State bundle layout

```text
{state_dir}/
├── hooks/
│   ├── terok-shield-createRuntime.json
│   └── terok-shield-poststop.json
├── terok-shield-hook              # entrypoint script (stdlib-only)
├── ruleset.nft                    # pre-generated nft ruleset (gateways baked in)
├── upstream.dns                   # persisted upstream DNS address
├── dns.tier                       # persisted active DNS tier
├── loopback.ports                 # per-container host-loopback TCP ports
├── profile.allowed                # IPs from DNS resolution (preset)
├── profile.domains                # domain names for dnsmasq config
├── live.allowed                   # IPs from manual allow/deny
├── live.domains                   # domains added at runtime via allow_domain
├── deny.list                      # persistent deny overrides
├── denied.domains                 # domains denied at runtime via deny_domain
├── dnsmasq.conf                   # generated dnsmasq configuration (dnsmasq tier)
├── dnsmasq.pid                    # dnsmasq PID (dnsmasq tier)
├── dnsmasq.log                    # dnsmasq query log (for `shield watch`)
├── resolv.conf                    # bind-mounted over /etc/resolv.conf (dnsmasq tier)
├── container.id                   # podman container ID (short, 12-char hex)
└── audit.jsonl                    # per-container audit log
```

`pre_start()` always writes the `hooks/` descriptors and the
`terok-shield-hook` entrypoint into the bundle, but podman only uses them
when per-container `--hooks-dir` persists across restarts. It does not
today — podman drops a per-container `--hooks-dir` across stop/start
([containers/podman#17935](https://github.com/containers/podman/issues/17935)) —
so shield instead installs the hooks once into a **global** directory
(`<state_root>/shield/hooks`, e.g. `~/.local/share/terok/shield/hooks`) and
registers that directory in podman's `containers.conf` (`hooks_dir` under
`[engine]`; `~/.config/containers/containers.conf` for rootless). `terok-shield
setup` installs the global hooks and patches `containers.conf`; the rest of the
bundle above stays per-container regardless.

### Data flow diagrams

**`deny_ip` flow:**

```text
deny_ip(container, ip)
│
├── safe_ip(ip)                 validate + normalize
│
├── nft delete element          remove from allow set
│   (best-effort, catch         (IP may not be in set if
│    ExecError)                  already denied earlier)
│
├── remove from live.allowed    always runs regardless
│                               of nft success
│
├── nft add element             add to deny_v4/v6 set
│   (best-effort)               (blocks dnsmasq re-allow)
│
└── append to deny.list         (deduplicated; deny decisions
                                 stick across restarts)
```

**`allow_ip` flow:**

```text
allow_ip(container, ip)
│
├── safe_ip(ip)                 validate + normalize
│
├── ip in deny.list?
│   └── yes → remove from deny.list     (un-deny)
│             + nft delete from deny set
│
├── nft add element             add to allow set
│                               (timeout 0s on the dnsmasq tier,
│                                so it never auto-expires)
│
└── append to live.allowed      (deduplicated)
```

**`shield_up` (effective IP merge):**

```text
StateBundle.read_effective_ips()
│
├── read_allowed_ips()
|   |
│   ├── profile.allowed ──┐
│   └── live.allowed ─────┤
│                         │
│                         ▼
│              union (dedup, profile-first)
│
├── read_denied_ips()
|   |
│   └── deny.list ──→ deny set
│
└── effective = allowed − denied
         │
         ▼
  add_elements_dual()       flat IP list to nft
  (nft/rules.py boundary)   (deny.list already subtracted;
                             deny sets repopulated from deny.list)
```

The OCI hook does not merge at start time — it applies the pre-generated
`ruleset.nft`, which `pre_start()` built from the same effective-IP merge.

## Audit logging

### JSON-lines lifecycle logs

Each container has its own audit log at `{state_dir}/audit.jsonl`. Every
lifecycle step logs a separate entry — actions are `setup`, `allowed`,
`denied`, `shield_up`, `shield_down`, and `shield_quarantine`:

```json
{"ts":"...","container":"myproj-1","action":"setup","detail":"profiles=dev-standard"}
{"ts":"...","container":"myproj-1","action":"allowed","dest":"93.184.216.34","detail":"target=example.com"}
{"ts":"...","container":"myproj-1","action":"shield_down","detail":"allow_all=True"}
```

Audit logging is best-effort — write failures are logged as warnings and
ignored to avoid blocking container operations.

### Kernel per-packet logs

nftables rules log per-packet events via NFLOG (`log group 100`) — written
to the kernel log and delivered over netlink to userspace consumers
(`terok-shield watch`, the per-container NFLOG reader):

- `TEROK_SHIELD_ALLOWED:` new connections to the allow set, logged and counted
  (not rate-limited -- established traffic is accepted earlier in the chain)
- `TEROK_SHIELD_DENIED:` traffic rejected by the explicit deny set (operator refused)
- `TEROK_SHIELD_PRIVATE:` non-allowlisted private-range traffic rejected (RFC 1918 + RFC 4193/4291)
- `TEROK_SHIELD_BLOCKED:` traffic rejected by the terminal default-deny rule (unclassified)
- `TEROK_SHIELD_BYPASS:` traffic passing while the shield is bypassed

## Public API

The package exports a `Shield` facade class for integration with
[terok](https://github.com/terok-ai/terok):

```python
from pathlib import Path
from terok_shield import Shield, ShieldConfig
shield = Shield(ShieldConfig(state_dir=Path("/path/to/state")))
```

| Method | Purpose |
|--------|---------|
| `pre_start(container, profiles)` | Install hooks, resolve DNS, return extra podman args |
| `allow(container, target)` | Live-allow a domain/IP for a running container |
| `deny(container, target)` | Live-deny a domain/IP (best-effort) |
| `down(container, container_id, allow_all=False)` | Switch to bypass mode (accept-all + log) |
| `up(container, container_id)` | Restore deny-all mode |
| `quarantine(container)` | Total network blackout (drop all, log dropped traffic) |
| `state(container)` | Query container shield state (`QUARANTINE`, `UP`, `DOWN`, `DISENGAGED`, `OFFLINE`, `ERROR`) |
| `rules(container)` | Return current nft ruleset for a container |
| `resolve(profiles, force=False)` | Resolve DNS profiles and cache results |
| `status()` | Return mode, profiles, audit config |
| `check_environment()` | Probe podman/hooks/DNS-tier health for consumers |
| `preview(down, allow_all)` | Show ruleset that would be applied |

`container_id` on `up` / `down` is the full podman UUID; it routes the
best-effort shield_up/shield_down hub events to the supervisor's
per-container socket.

`ShieldConfig` is a frozen dataclass with required `state_dir: Path` and
optional mode, default profiles, loopback ports, profiles dir, audit
settings, and container runtime category (`ShieldRuntime`). The library
never reads environment variables or config files — all configuration
comes from the caller.

terok imports terok-shield as a library dependency and calls the Python API
directly — never the CLI.

## Module structure

| Module | Role |
|--------|------|
| `__init__.py` | `Shield` public API facade + lazy re-exports |
| `nft/rules.py` | `RulesetBuilder` — ruleset generation, input validation, verification |
| `nft/constants.py` | Shared literals (`NFT_TABLE`, private ranges, log prefixes) — no logic |
| `config.py` | `ShieldConfig`, `ShieldMode`, `ShieldState`, `ShieldRuntime`, `DnsTier`, `ShieldModeBackend` protocol, annotation constants |
| `state.py` | `StateBundle` — per-container state bundle layout, effective IP merging |
| `hooks/mode.py` | `HookMode` strategy (OCI hooks, per-container netns, dnsmasq lifecycle) |
| `hooks/install.py` | Hook installation — entrypoints, JSON descriptors, `containers.conf` patch |
| `hooks/reader_install.py` | NFLOG reader resource installer |
| `dns/resolver.py` | DNS resolution via `dig` / `getent`, file-based caching |
| `dns/dnsmasq.py` | dnsmasq config generation, reload, domain add/remove |
| `dns/apparmor.py` | AppArmor confinement probe + DNS tier selection |
| `profiles.py` | Profile loading and composition |
| `audit.py` | JSON-lines audit logging (single file per container) |
| `run.py` | Subprocess wrappers (`nft`, `nsenter`, `dig`, `podman`) |
| `validation.py` | Input validation (container names, allowlist entries) |
| `util.py` | Small shared utilities |
| `paths.py` | Host-wide paths and filenames (hook entrypoint name, reader script path) |
| `podman_info/` | `podman info` parsing, hooks-dir discovery, network mode/gateways |
| `commands.py` | Command registry — subcommand definitions, metadata, and reusable handlers |
| `cli/main.py` | Standalone CLI entry point + config construction from env/YAML |
| `watch.py`, `watchers/` | `terok-shield watch` — DNS-log / audit-log / NFLOG event streams |
| `resources/nft_hook.py` | Stdlib-only OCI hook script — applies `ruleset.nft`, manages dnsmasq |
| `resources/reader_hook.py`, `resources/nflog_reader.py` | Bridge hook + per-container NFLOG reader |
| `resources/_oci_state.py` | Shared stdlib-only ballast imported by the hook scripts |

Module boundaries are enforced by [tach](https://github.com/gauge-sh/tach)
(`tach.toml`). `nft/rules.py` may only import from `nft/constants.py` and stdlib.
