# CLI Reference

All commands are invoked as `terok-shield <command> [options]`.

Global options:

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--state-dir <path>` | Override state root directory |

## run

Launch a shielded container via podman. Resolves DNS, checks setup, and
execs into `podman run` with the correct flags.

```bash
terok-shield run <container> [--profiles <profile>[,<profile>...]] -- <image> [cmd...]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name |
| `--profiles` | Profiles to apply (comma-separated); without it, the `default_profiles` from `config.yml` apply |
| `-- ...` | Everything after `--` is passed to `podman run` |

```bash
# Basic usage
terok-shield run my-container --profiles dev-standard -- alpine:latest sh

# Multiple profiles
terok-shield run my-container --profiles dev-standard,dev-python -- alpine:latest sh

# With extra podman flags (after --)
terok-shield run my-container -- --rm -it -e FOO=bar alpine:latest sh
```

Shield-managed flags (`--name`, `--hooks-dir`, `--annotation`, `--cap-drop`,
`--cap-add`, `--security-opt`, `--network`) are set automatically and rejected
if passed after `--`.

On a DNS tier that resolves names itself, `run` and `prepare` print to stderr
which names it pins to the addresses they resolved to — allowlisted names a
rotation would break, break-glass overrides, and, on `lookup` and `getent`,
denied names a rotated address would escape. See
[Pinned names](modes.md#pinned-names-and-the-rotation-warning).

`run` and `prepare` author the container's state bundle (`ruleset.nft`, the
policy tiers, the audit log) under
`$XDG_STATE_HOME/terok/shield/containers/<container>` — or under the global
`--state-dir` root when given — and stamp that path into the container's
`terok.shield.state_dir` annotation. Every other verb finds the bundle through
that annotation, so it works on any shielded container regardless of who
launched it.

## prepare

Resolve DNS, install hooks, and print the podman flags needed to launch a
shielded container. Useful for scripting or inspecting what `run` would do.

```bash
terok-shield prepare <container> [--profiles <profile>[,<profile>...]] [--json]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name |
| `--profiles` | Profiles to apply (comma-separated); without it, the `default_profiles` from `config.yml` apply |
| `--json` | Output as a JSON array (machine-readable) |

```bash
# Shell-quoted output (default)
terok-shield prepare my-container
# --hooks-dir /home/user/.local/state/... --annotation ... --name my-container

# Use with eval for manual podman invocations
eval "podman run $(terok-shield prepare my-ctr) alpine:latest sh"

# JSON output for programmatic consumption
terok-shield prepare my-container --json
# ["--hooks-dir", "/home/user/.local/state/...", "--name", "my-container"]
```

Only the flags go to stdout, so `eval` sees nothing else; the DNS tier's
hint and the names it pins go to stderr.

## status

Show current shield status, or query a specific container's firewall state.

```bash
terok-shield status [container]
```

| Argument | Description |
|----------|-------------|
| `container` | Optional — when given, prints the container's firewall state |

Without a container name, shows the global shield configuration:

```bash
terok-shield status
```

```text
Version:            0.8.0
Podman:             5.4.0
Mode:               hook
Hooks:              global
Health:             ok
Audit:              enabled
Available profiles: base, dev-node, dev-python, dev-standard, krun_guest, nvidia-hpc
```

With a container name, prints the live firewall state (`up`, `down`, `disengaged`,
`offline`, or `error`). Useful for scripting and integration:

```bash
terok-shield status my-container
# up
```

An open [bypass window](#bypass) rides on the same line, so a widened UP is
never mistaken for the ordinary one:

```bash
terok-shield status my-container
# up (bypass window open, 4m59s left)
```

Both come from one `nft -T list table` inside the container — the listing that
classifies the posture already holds the window set — and the countdown is the
kernel's own, in whole seconds. The library call is `Shield.inspect(container)`,
which returns both as a `ShieldReading`.

## resolve

Re-resolve a prepared container's policy into its resolution caches: the
allowlist it launched with, its break-glass overrides, and its security denies.
`resolve` rewrites no policy. On `dnsmasq-live`, dnsmasq resolves allowed
domains per query, so `resolve` says so instead of printing an allow count.

```bash
terok-shield resolve <container> [--force]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name (used as the cache key) |
| `--force` | Re-resolve every domain even when the cache is fresh |

```bash
terok-shield resolve my-container
# Resolved 28 IPs for my-container

terok-shield resolve my-container --force
# Resolved 28 IPs for my-container (forced)
```

Cached IPs are stored in the container's `resolved.ips` file and
automatically refreshed when stale (default: 1 hour).

## allow

Add a domain or IP to a container's allow set — live while it runs, from its
next start while it is stopped.

```bash
terok-shield allow <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to allow |

```bash
terok-shield allow my-container example.com
# Allowed example.com -> <resolved-ip> for my-container

terok-shield allow my-container 203.0.113.10
# Allowed 203.0.113.10 -> 203.0.113.10 for my-container
```

If `target` is a domain name, it is resolved to IPs automatically.
Changes take effect immediately. The allow is persisted to the `policy/live`
overlay (as a `+` line) and survives `down`/`up` posture cycles. If you denied
the target earlier, the allow flips that verdict automatically.

**The security tier is not yours to flip.** A target the t20 security tier
denies — a vault-relayed provider host the orchestrator keeps the agent from
reaching directly — is refused, and so is any name under one of its domains
and anything that resolves to one of its addresses (a CDN front sharing an
address with a vault host, say). The verb exits non-zero, nothing is granted,
and the message names the shared address when that is the cause:

```bash
terok-shield allow my-container cdn.example.net
# Error: cdn.example.net shares the address 203.0.113.7 with the security tier
#   — break-glass only: use a shield.override (reason + expires) to reach it directly
```

Only a break-glass [override](#override) (the t10 tier, above the deny) reaches
such a host, and the refusal lands in the audit log as `allow_refused`. On the tiers without
dnsmasq (`lookup`, `getent`) nothing sinkholes a vault host's name, so its
address can rotate past the cached resolution: `allow` re-resolves the
security tier's names first, and a rotated address is refused all the same.

**A stopped container** has no ruleset to change, so the target is recorded in
its `policy/live` overlay instead — the name itself for a domain — and the
files the OCI hook applies at the next start (`ruleset.nft`, the dnsmasq
config) are rewritten from the bundle at once, so the verb's promise holds
for a plain `podman start` too:

```bash
terok-shield allow my-container example.com
# my-container is not running: recorded example.com in its runtime overlay,
#   which applies at its next start
```

On a tier that pins names the domain is resolved then, its addresses seeding
the new ruleset; on `dnsmasq-live` the rewritten config learns them per query.
A restart through terok re-derives the whole bundle anyway — the same path
that carries any runtime allow across a restart.

## deny

Remove a domain or IP from a running container's allow set.

```bash
terok-shield deny <container> <target>
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name or IP address to deny |

```bash
terok-shield deny my-container example.com
# Denied example.com (<resolved-ip>) for my-container
```

The IP is removed from the nft `t40_project_allow` set (if present; errors are
logged but do not prevent the deny from being persisted) and added to the
`t20_security_deny` set. The deny is recorded as a `-` line in the `policy/live`
overlay, so it persists across `up`/`down` cycles and container restarts and
flips any prior allow of the same target.

## down

Switch a container to the DOWN posture. Public traffic is accepted with
logging; private ranges (RFC 1918/RFC 4193) remain blocked unless
`--disengage` is used.

```bash
terok-shield down <container> [--disengage]
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `--disengage` | Enforce nothing — lift the deny set and every range reject (DISENGAGED posture) |

Plain DOWN keeps three rejects: the hard-deny floor (link-local, IMDS),
the security-deny set, and the private ranges (RFC 1918, RFC 4193).
`--disengage` lifts all three. The DISENGAGED posture accepts every
destination and logs each new connection.

Both postures still match the allow tiers first and log those accepts as
`TEROK_SHIELD_ALLOWED`, as UP does. What reaches the closing
`TEROK_SHIELD_DOWN` line is therefore exactly what UP would have refused, and
the audit log records it as `down` — a task can run down and still be
[harvested](#harvest).

A t10 override opens one private host or one private range in every
enforcing posture. Shield logs a CIDR override as a warning. The
private-range reject sits above the allow tiers, so an allowlist entry does
not open a private address. The hard-deny floor sits above t10, so no
override reaches a link-local or IMDS address.

On `lookup` and `getent`, a plain `down` prints to stderr the denied names
whose deny now holds only the addresses they resolved to: down accepts by
default, so an address a vault host rotates to is accepted. Before it
rebuilds, `down` re-resolves the caches older than an hour or than the policy,
so that deny holds the current addresses. See
[Pinned names](modes.md#pinned-names-and-the-rotation-warning).

## up

Restore normal deny-all mode for a container.

```bash
terok-shield up <container>
```

Re-applies the deny-all ruleset and restores the effective allow IPs
(the composed `policy/` tiers with the runtime overlay, minus the
security-deny tier). Allow-set state the container learned through dnsmasq
survives the transition — a down/up round trip never forgets IPs the
workload already resolved. Break-glass overrides are re-seeded timed to what
is left of their expiry.

On a tier that resolves names itself, `up` first re-resolves the caches older
than an hour or than the policy, then prints to stderr the names the tier
still pins: allowlisted, break-glass and, on `lookup` and `getent`, denied. See
[Pinned names](modes.md#pinned-names-and-the-rotation-warning).

## bypass

Open, close, or show the timed allow-all window — the escape hatch for the
moment a task needs something the policy does not name yet.

```bash
terok-shield bypass <container>                 # how long is left
terok-shield bypass <container> --for 5m        # open it
terok-shield bypass <container> --off           # close it now
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `--for` | Open the window for this long (a non-zero nft timeout such as `30s`, `5m`, `2h`); defaults to `bypass_duration` |
| `--off` | Close the window now |

While the window is open, a connection the allowlist would refuse is accepted
instead of hitting the terminal reject. The window sits below every deny in
the chain: the security tier (vault hosts), the private ranges (RFC 1918,
RFC 4193) and the hard-deny floor (link-local, IMDS) all stay refused. Each
accepted connection is logged with the `TEROK_SHIELD_BYPASS` prefix and
recorded in `audit.jsonl` as `bypass`, so what the window let through can be
read back afterwards — and promoted into the policy if it belongs there.

The window opens only in the UP posture, because only the UP chain reads its
set. `--for` refuses any other posture rather than report a window that
grants nothing: DOWN accepts by default already, and quarantine drops
everything.

The window lives in the kernel. Its element carries a timeout, so it closes
itself when the timeout runs out, and any disruption — a `shield up`, a
restart, a host process that dies — closes it sooner rather than later.
Nothing renews it, and there is no host-side deadline to go stale: the
countdown the bare verb prints is read straight from nft, in whole seconds
(`nft -T`), from the window's own set. A zero duration (`0s`, `0m`) is
refused, here and as `bypass_duration`: nft reads `timeout 0s` as *never*,
which would open a window no countdown reports. Opening the window while one
is open replaces its countdown, so `--for 1m` also shortens a longer window.
A ruleset holding a window element with no timeout at all is not reported as
UP — `status` says `error`, and the bare verb refuses to read a window from it
(`--off` still closes it):

```bash
terok-shield bypass my-container
# Bypass window open for my-container, 4m59s left
```

## override

Break glass for one host, address or range on a running container: the one
way past the security tier. `--off` revokes a break-glass before it expires.

```bash
terok-shield override <container> <target> --expires <YYYY-MM-DD> --reason <text>   # open it
terok-shield override <container> <target> --off                                    # revoke it now
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `target` | Domain name, IP address or CIDR |
| `--expires` | The last day the override holds, `YYYY-MM-DD`, host local time. Required to grant |
| `--reason` | Why the break-glass is needed. Required to grant; recorded and audited |
| `--off` | Revoke the override now. Takes neither `--expires` nor `--reason` |

An override adds the target to the t10 set, which sits above the security tier
and the private ranges. That gives direct reach to a vault-relayed provider
host, or to a LAN service in a private range. Agents keep reaching a
vault-relayed provider through the vault for its keys; the override only adds
the direct route. A name is resolved once, so the addresses checked are the
addresses opened; the override cache takes them only once the grant is
recorded. On the `dnsmasq-*` tiers it is also opened in the DNS sinkhole, so
the workload can resolve it.

```bash
terok-shield override my-container api.vendor.example --expires 2026-11-30 --reason "vendor outage"
# Override open for my-container: api.vendor.example -> 203.0.113.7
# Valid through 2026-11-30: the kernel closes it at the end of that day, host local time
# That stops new connections only: any already open keep running until they close
```

**Expiry.** `--expires` takes a date, and the override is valid *through* that
date. It runs out at the host's local midnight that ends the day, so
`--expires` set to today holds until tonight. A date already past is refused.
The kernel enforces the expiry. Each address is a t10 element whose timeout is
the seconds its override has left, so nothing in userspace keeps the clock and
a crashed host process cannot stretch it. Every `up` / `down` rebuild re-times
the elements from the same deadline.

**Reason.** A grant needs both flags, because a break-glass has to say how long
it holds and why it exists. The reason is recorded on the override's tier entry
(`policy/10-override`, as a `%reason` marker beside its `%expires`) and in the
audit log. The audit log gets the grant as an `override` event the moment the
nft transaction commits.

**What it can never open.** Two things sit above t10 and stay closed. One is
the hard-deny floor: IPv4 link-local (`169.254.0.0/16`, cloud metadata
included), IPv6 link-local (`fe80::/10`) and the AWS IPv6 IMDS. The other is
the host's own loopback, the address `host.containers.internal` names: pasta's
host-loopback map, or the slirp4netns gateway. An override there would open
every port the host listens on locally. A `+localhost:PORT` grant reaches a
host service instead, one port at a time. `localhost`,
`host.containers.internal` and `*.` wildcards are refused as targets. So is a
name that resolves into the floor or onto the host, or to no address at all.
An address is refused before the posture is read, so the message is the same
on a stopped container:

```bash
terok-shield override my-container 169.254.169.254 --expires 2026-11-30 --reason "metadata"
# Error: 169.254.169.254 reaches 169.254.169.254, inside the hard-deny floor 169.254.0.0/16:
#   link-local and cloud-metadata addresses sit above every override, so none is granted
```

The ruleset enforces both, not only the grant. pasta's map lies inside the
link-local floor, and under slirp4netns the ruleset refuses the gateway in
t00 as well, past the ports its preamble opens. So nothing in t10 reaches
either: not an authored range around the gateway, and not a name whose
answer changes after its grant. A grant checks only its own target's
answer, yet it re-resolves every override name, and so do a re-resolve and a
rebuild over a stale cache. An address such a refresh turns up on the host's
loopback or the floor is left out of t10 and noted in the log and the audit
trail. A break-glass name that starts resolving to the host is what a DNS
rebinding looks like:

```text
t10 override api.vendor.example reaches 10.0.2.2, the host's own loopback
  (host.containers.internal): no override opens it, so the t10 set leaves it out
```

A grant needs a running ruleset with a t10 set: the UP, DOWN or DISENGAGED
posture. A stopped or quarantined container is refused. For those, author the
override as `shield.override` in the orchestrator's policy, and it applies from
the next start. A live grant lasts until it expires, or until a restart
through the orchestrator re-derives the tier from that policy. An override that
should outlive the task belongs in that policy.

### Revoking an override

`--off` ends an override before its expiry. It works the same on a live grant
and on one the orchestrator authored:

```bash
terok-shield override my-container api.vendor.example --off
# Override of api.vendor.example revoked for my-container: closed 203.0.113.7
# That stops new connections only: any already open keep running until they close
```

The revoke is ordered to fail closed:

1. The tier entry is removed first, so no later `up` / `down` rebuild
   re-opens the override.
2. The files the OCI hook replays at the next start (`ruleset.nft`,
   `override.expiry`) are rewritten without it, so a plain `podman start`
   does not re-open it either.
3. The running ruleset's t10 set is swapped in one nft transaction. The set is
   flushed and re-seeded with every override still in force, each timed to
   its own deadline.
4. For a name on a `dnsmasq-*` tier, dnsmasq reloads, so the name is
   sinkholed again.

If step 2 cannot write its files, steps 3 and 4 still run, and the error then
says a plain `podman start` would re-open the override until the next `up` /
`down`.

No DNS lookup takes part, so a revoke never waits on a resolver. The revoke is
audited as `override_revoked` once nothing running holds the override.

A target with no override in force is an error. That covers a target that never
had one and one whose override already expired:

```bash
terok-shield override my-container api.other.example --off
# Error: my-container has no override of api.other.example to revoke
#   (overrides in force: api.vendor.example)
```

`localhost` is refused too. A `+localhost:PORT` grant opens a host service in
the ruleset's preamble and is not an override, so `--off` cannot take it back.

A revoke can fail partway, and the verb then exits non-zero and says how far it
got. If nft cannot drop the elements, the record is already gone, so no rebuild
re-opens the override. The running ruleset still admits it until the next `up`
or `down`, and no `override_revoked` event is written. If dnsmasq cannot reload,
the address-level revoke has already happened, and the error names the name it
could not sinkhole. The same holds when no dnsmasq runs at all (its PID file
is gone): the config on disk sinkholes the name again for the next start, and
the error says nothing serves it before then.

An address the revoked override held can stay reachable through another
override that covers it, a range for instance. The verb lists those addresses
separately instead of reporting them closed:

```bash
# Still open above the security tier through another override: 192.0.2.77
```

A stopped container has no ruleset to change. The record, the files its next
start replays and its dnsmasq config are rewritten, and the verb says the
revoke applies from that start. "Stopped" is podman's answer: a ruleset that
cannot be read reads as no ruleset, so the revoke asks podman whether the
container has a process; one podman has no record of counts as stopped too. A
running one gets the t10 swap, and its failure is reported. When podman cannot
answer either, nothing is changed and the error says to try again. A revoke stops new connections. Connections
already established keep running until they close, the same as when an
override expires, and the verb says so. A revoke also holds only until a
restart through the orchestrator re-derives the tier: an override authored in
that policy comes back unless it is removed there as well.

## harvest

Show what a container reached for, read back out of its audit log.

```bash
terok-shield harvest <container>          # what can be promoted first, the floor last
terok-shield harvest <container> --json   # the same report, machine-readable
```

| Argument | Description |
|----------|-------------|
| `container` | Container name or ID |
| `--json` | Emit the report — the entries and whether audit was on — as JSON instead of a table |

Nothing new is collected: the NFLOG reader already writes one line per
destination for what the workload's traffic met — `blocked` (the terminal
refusal), `bypass` (let through by the timed window), `down` (accepted only
because the shield was down), `security_deny` (refused by the t20 deny set) and
`private_range` (refused by a range floor) — and `harvest` folds those into one
entry per target, the unit a promotion decision is made in. The target is the
domain when the reader recovered one from the DNS cache and the address
otherwise, because an allowlist entry for a rotating CDN is worth nothing as an
IP. On the DNS tiers without dnsmasq the reader has no DNS cache, so every
target is an address.

The count is a floor on attempts, not a connection count: the reader records at
most one line per target per 30 seconds, so a tight retry loop and a single
request can both land as one.

Each entry names the tier that stands between the task and the target, and the
remedies that could lift it, in preference order. The tier is read from the
destination against the container's own policy, never from the log line's
action alone — one log prefix covers the hard-deny floor and the private ranges
alike, a DISENGAGED shield records a vault host as `down`, and quarantine drops
are recorded as `blocked`:

| Tier | What refuses the target | Remedies |
|------|-------------------------|----------|
| `t40` | Nothing but the allowlist's silence | `task`, `project`, `set` |
| `t20_operator` | The operator's own runtime deny (`policy/live`) | `task`, `project` |
| `t20_security` | The security tier — by name, by a domain above it, or by address; vault-relayed hosts above all | `override` |
| `t20_private` | A private range (RFC 1918, RFC 4193) | `override` |
| `t00` | The hard-deny floor (link-local, IMDS), and the host's own loopback beside it | none — except `host_port` for `host.containers.internal` (pasta's map, or the slirp4netns gateway), which a `+localhost:PORT` grant reaches |

A name behind several addresses takes the most restrictive of their tiers: a
remedy has to work for all of them. Entries come in that order too — what can
be promoted outright first, break-glass next, the floor last.

When the container was created with audit disabled, its reader recorded
nothing, and `harvest` says so instead of reporting nothing harvested.

`harvest` changes no policy. Acting on what it shows — an entry in
`shield.allow`, a curated set, a break-glass `shield.override` — stays an
explicit act, and the tier that refused a host still decides whether it can be
promoted at all.

## reset

Forget DNS-learned allow-set state, returning the allow sets to their
just-launched contents.

```bash
terok-shield reset <container>
```

The live tier accumulates every IP the workload legitimately resolved
(elements also age out on their own via the set timeout). `reset` drops
that learned state in one transaction while re-seeding the authored policy
literals, and touches neither the deny tier nor runtime `allow`/`deny`
overlay entries. The workload re-earns its state on its next DNS queries.

## preview

Show the nftables ruleset that would be applied.

```bash
terok-shield preview [--profiles <profile>[,<profile>...]] [--down] [--disengage]
```

| Option | Description |
|--------|-------------|
| `--profiles` | Profiles to compose in (comma-separated); without it, the `default_profiles` from `config.yml` apply |
| `--down` | Show the DOWN-posture ruleset instead of default deny-all |
| `--disengage` | Show the DISENGAGED ruleset: no deny set, no range rejects (requires `--down`) |

With `--profiles`, the output is the ruleset the OCI hook applies at
`createRuntime` for those profiles on the live tier: their `+localhost:PORT`
grants sit in the preamble and their literal IPs seed the project-allow set.
Domains are deliberately absent — the live tier never resolves them at apply
time (dnsmasq learns them per query), so nothing is approximated. `preview`
needs no `setup`, no podman and no state directory, which makes it the
generator for applying a ruleset by hand.

### Applying a ruleset by hand

A container that may reach one service on the host and nothing else, without
the OCI hook:

```bash
echo '+localhost:9931' > ~/.config/terok/shield/profiles/llm.txt
terok-shield preview --profiles llm > rules.nft

podman create --name llm \
    --network pasta:--map-host-loopback,169.254.1.2 \
    --add-host host.containers.internal:169.254.1.2 \
    --cap-drop NET_ADMIN --cap-drop NET_RAW \
    alpine:latest sh
podman init llm
podman unshare nsenter -t "$(podman inspect -f '{{.State.Pid}}' llm)" -n nft -f - < rules.nft
podman start llm
```

The network flags must use the same host-loopback map address the ruleset was
generated for (`169.254.1.2`); `podman init` creates the network namespace
before the entrypoint runs, so the rules are in place first. Without the hook
nothing re-applies them: repeat the `nsenter` line after every `podman start`.

## rules

Display the active nftables rules for a container.

```bash
terok-shield rules <container>
```

Shows the container's shield state and the full nftables ruleset in its
network namespace.

## profiles

List available shield profiles.

```bash
terok-shield profiles
```

```text
base
dev-node
dev-python
dev-standard
nvidia-hpc
```

Lists both bundled profiles and any user-defined profiles from the
config profiles directory.

## logs

Show audit log entries.

```bash
terok-shield logs [--container <name>] [-n <count>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--container` | all | Filter by container name |
| `-n` | 50 | Number of recent entries to show |

```bash
terok-shield logs --container my-container -n 10
terok-shield logs -n 5   # last 5 entries across all containers
```

Each entry is a JSON object printed on one line. See [Audit Logging](logging.md)
for the log format.
