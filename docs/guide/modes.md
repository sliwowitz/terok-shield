# Firewall Modes

terok-shield uses **hook mode** — an OCI hook that applies nftables rules inside
each container's own network namespace.

## Hook mode

Self-contained. Uses an OCI hook to apply nftables rules inside each container's
own network namespace.

```text
┌──────────────────────────────────────────┐
│ Container netns                          │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ nftables (applied by OCI hook)     │  │
│  │ policy: DROP                       │  │
│  │ allow: DNS, lo, @t40_project_allow │  │
│  │ reject: RFC1918, RFC4193           │  │
│  └────────────────────────────────────┘  │
│                                          │
│  Workload (CAP_NET_ADMIN dropped)        │
└──────────────────────────────────────────┘
```

### How it works

1. `Shield.pre_start()` verifies the setup-installed global hooks,
   processes the allowlist profiles, and pre-generates the complete nft
   ruleset to `ruleset.nft`. On the live tier the composed policy lands in
   `policy/40-project-allow` and only literal IP entries seed the sets; on every
   other tier the domains are resolved now, into `resolved.ips`, and the
   terminal says so (see [DNS tiers](#dns-tiers)).

   Returns podman args with OCI annotations (`state_dir`, `loopback_ports`,
   `version`, `upstream_dns`, `dns_tier`)
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the stdlib-only hook script at the `createRuntime` stage
3. The hook reads `state_dir` from annotations and applies the pre-generated
   `ruleset.nft` (gateway addresses already baked in at `pre_start`) inside the
   container's network namespace via `nsenter`, then resolves `dnsmasq.command`
   against the current host `PATH` and starts it when `dnsmasq.conf` is present.
   If `PATH` is absent (not merely empty), the hook uses setup's captured search path.
4. On the live tier dnsmasq runs with `--nftset` pointing to the
   `t40_project_allow_v4`/`t40_project_allow_v6` sets — every DNS resolution
   adds the resolved IPs to the live nft project-allow sets before the answer
   reaches the workload
5. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### DNS tiers

Shield picks the best tier the host supports and records it per container.
Only the first tier resolves live; the others resolve the allowlist at launch
and refresh a stale resolution on a `shield up` or `shield down` (see
[Pinned names](#pinned-names-and-the-rotation-warning)), so they cannot follow
an address that rotates in between.

| Capability | `dnsmasq-live` | `dnsmasq-static` | `lookup` | `getent` |
|---|---|---|---|---|
| Allow sets follow IP rotation | yes | no | no | no |
| Subdomains of an allowed domain reachable | yes | no | no | no |
| Wildcard entries such as `*.example.com` | yes | refused at launch | refused at launch | refused at launch |
| Blocked-connection events carry the name | yes | yes | IP only | IP only |
| Denied names fail fast with NXDOMAIN | yes | yes | no | no |
| A denied name stays denied after its address rotates | yes (sinkholed by name) | yes (sinkholed by name) | no — its resolved addresses only | no — its resolved addresses only |
| Break-glass overrides follow IP rotation | no | no | no | no |
| `allow name` while running | addresses now, rotation later | addresses now | addresses now | addresses now |
| Host needs | dnsmasq built with nftset support | any dnsmasq | `dig` or `drill` | glibc only |

To reach the live tier, install the distro's dnsmasq (`dnsmasq-base` on Debian
and Ubuntu). Distros whose package lacks nftset support (the RHEL 9 and 10
family, Ubuntu 22.04, Gentoo, Alpine's default package) land on
`dnsmasq-static`; a dnsmasq built from source with `COPTS=-DHAVE_NFTSET`, for
example in your home, restores the live tier without root. Point shield at it
with `dnsmasq_path` (see [Configuration](configuration.md#dnsmasq-binary)).

### Pinned names and the rotation warning

A name the shield resolves itself is enforced by the addresses it resolved
to, and the provider behind it can move to another address at any time. Which
names that affects depends on the tier:

- **Allowlisted names** (t30, t40, runtime `allow`) on every tier but
  `dnsmasq-live`. While the shield is up, a connection to an address the
  name rotates to is refused.
- **Denied names** (the t20 security tier, runtime `deny`) on `lookup` and
  `getent`, where no dnsmasq sinkholes them by name. The deny holds only their
  resolved addresses, so an address a vault host rotates to escapes it: while
  the shield is down, or while up through an allowlisted name that shares the
  address or an open bypass window. This one is a security gap, not a
  convenience one.
- **Break-glass override names** (t10) on *every* tier, `dnsmasq-live`
  included: dnsmasq never populates the override set, so an override always
  reaches only the addresses its name resolved to.

IP and CIDR entries cannot rotate, and neither can `localhost`, any
`*.localhost` name, or `host.containers.internal` (shield pins it to the host
address itself), so they are never listed.

Shield says which names it pins, worded for the posture:

- at launch and at every restart that re-authors the bundle, in the log and as
  an audit `note`; `terok-shield prepare` and `run` also print it to stderr;
- on `shield up`, every kind, and on a plain `shield down`, the denied names
  alone — in the log, as audit `note`s, and on stderr from the CLI verbs. A
  DISENGAGED shield enforces nothing, so it has nothing to say.

The same reading is available without any of those: `recorded_rotation_risk(state_dir)`
computes it from the bundle on demand, so an orchestrator can show it in a
task view with no running container to ask, and with audit disabled.

Shield also narrows the gap where it can. On the tiers that pin names, `shield
up` and `shield down` re-resolve every resolution cache older than an hour, or
older than the policy — which a runtime `allow`, `deny` or break-glass
rewrites — before they rebuild the table, so the sets they seed, and the deny
set the DOWN posture keeps enforcing, take the names' current addresses. A
resolve in which no name answers keeps the previous addresses rather than
none while the policy is unchanged, and the deny caches go further: they keep
one line per name, so a vault host whose lookup alone times out keeps its
previous addresses while the others take their new ones — a failed lookup
never drops a name's addresses out of the deny.

### Chain evaluation order

```text
preamble (lo, established, DNS, infra ports, +localhost grants) → t00 hard-deny (link-local + IMDS + the host's own loopback) → t10 override (each element kernel-timed to its expiry) → t20 security-deny (@t20_security_deny + RFC1918/RFC4193) → t30 provider allow → t40 project allow → bypass window (UP only) → terminal reject (log BLOCKED)
```

The bypass window sits below every deny: while it is open, a connection the
allowlist would refuse is accepted and logged, but vault hosts, private ranges
and the hard-deny floor stay refused. Only the UP chain reads it, so it cannot
be opened in any other posture.

### Break-glass overrides and their expiry

A t10 override is the one way past the security tier: direct reach to a
vault-relayed provider host, or a LAN service in a private range. Agents keep
reaching a vault-relayed provider through the vault for its keys; the override
only adds the direct route. The hard-deny floor (link-local, cloud metadata)
sits above t10 and is never overridden.

An override line may carry `%expires=<date>`, valid *through* that day — it
runs out at the host's local midnight that ends it — or an ISO timestamp for
an exact instant. The kernel enforces it: each override address is an element
with a timeout of the seconds its override has left, as the bypass window's
element is, so the break-glass ends on time with nothing in userspace keeping
the clock. An override that has already run out is dropped when the bundle is
authored, and noted in the audit log as `override_expired`. Every rebuild
(`shield up`, `shield down`) re-times the elements from their deadlines.

`ruleset.nft` is replayed verbatim at every start of the container, so a
relative timeout baked into it would re-grant an override for its full span on
a restart days later. Overrides that expire stay out of it: `override.expiry`
lists their addresses with absolute deadlines, and the OCI hook times them
when it applies the ruleset, in the same transaction.

`Shield.override(container, target, expires, reason=...)` breaks glass on a
running container: it records the target in the t10 tier with its expiry and
its reason — both required — re-seeds the whole override set in one nft
transaction, audits the grant as `override` the moment that transaction
commits, and, for a name on a dnsmasq tier, opens the name in the sinkhole so
the workload can resolve it. The grant survives `shield down`/`shield up` until
it expires; the next restart re-derives the tier from the orchestrator's
policy, which is where an override that should outlive the task belongs. The
host's own loopback is refused like the hard-deny floor — under slirp4netns
that is the gateway `host.containers.internal` names, inside a private range —
because a `+localhost:PORT` grant reaches a host service one port at a time,
where an override would open them all. The ruleset enforces it too: `t00`
refuses the slirp4netns gateway above t10, past the preamble's ports, and the
t10 seed leaves out any address on the host's loopback or in the floor that a
later re-resolve of an override name turns up, noting it in the log and the
audit trail.

`Shield.revoke_override(container, target)` (the CLI's
[`override --off`](cli.md#revoking-an-override)) ends an override before its
expiry, whether it was granted live or authored. It removes the tier entry
first, so no rebuild re-opens it. It then rewrites the `ruleset.nft` /
`override.expiry` a start replays, and swaps the running t10 set without it in
one transaction. A name is sinkholed again. The revoke is audited as
`override_revoked`, and a target with no override in force is an error. A
container counts as stopped only when podman says it has no process, or has
no such container, never because its ruleset could not be read. A revoke, like
an expiry, stops new connections only: those already open keep running until
they close.

The kernel ends the address plane on time; the DNS plane follows at the next
rebuild. A running dnsmasq keeps the config it loaded, so a name opened by an
override that has since run out still resolves until the next `shield up` /
`down` reconciles the config (or a restart through the orchestrator rewrites
it) — see [Break-glass expiry](../security.md#break-glass-expiry-is-kernel-enforced).

### When to use

- Single containers or small deployments
- When you want per-container isolation (each container has its own firewall)
- Simplest setup — just needs `nft` binary

### Per-container state bundle

Each container's state is isolated in its own directory:

```text
{state_dir}/
├── policy/                                 # v15 tiered +/- policy, one file per tier set
│   ├── 10-override                         #   → nft set t10_override (break-glass allow)
│   ├── 20-security-deny                    #   → nft set t20_security_deny (vault hosts + operator deny)
│   ├── 30-provider-allow                   #   → nft set t30_provider_allow (provider egress)
│   ├── 40-project-allow                    #   → nft set t40_project_allow (project allowlist)
│   └── live                                #   Runtime allow/deny overlay (+/- lines)
├── resolved.ips                            # Resolved allow IPs (t40 seed; every tier but dnsmasq-live)
├── override_resolved.ips                   # Override names, each with the addresses it resolved to (t10 seed)
├── deny_resolved.ips                       # Security-tier names, each with its addresses (t20 seed)
├── live_deny_resolved.ips                  # policy/live denied names, each with its addresses (t20 seed)
├── ruleset.nft                             # Pre-generated nft ruleset (gateways baked in)
├── override.expiry                         # Expiring override addresses + deadlines (the hook times them)
├── dnsmasq.conf                            # Generated dnsmasq config (dnsmasq tiers)
├── dnsmasq.command                         # Launch command, resolved on each start
├── dnsmasq.pid                             # dnsmasq PID (dnsmasq tiers)
├── dnsmasq.bin                             # Live dnsmasq identity (cleanup only)
├── resolv.conf                             # Bind-mounted /etc/resolv.conf (every tier)
├── upstream.dns                            # Persisted upstream DNS address
├── dns.tier                                # Persisted active DNS tier
├── audit.enabled                           # Creation-time audit flag (the NFLOG reader honours it)
└── audit.jsonl                             # Per-container audit log
```

> **Global hooks.** `terok-shield setup` installs hooks under
> `<state_root>/shield/hooks` and registers them in `containers.conf`.
> Task preparation never modifies them; bare Podman restarts remain protected.

### Running containers

Via the CLI (recommended for standalone usage):

```bash
terok-shield run my-container -- my-image
```

Via the Python API (this is how [terok](https://github.com/terok-ai/terok)
uses terok-shield as a library):

```python
from pathlib import Path

from terok_shield import Shield, ShieldConfig

shield = Shield(ShieldConfig(state_dir=Path.home() / ".local/state/terok/shield/containers/my-ctr"))
extra_args = shield.pre_start("my-ctr", ["dev-standard"])
# pass extra_args to podman run
```

### dnsmasq and the nft allow sets

On the live tier the allow sets are populated dynamically — no manual
`terok-shield allow` calls are needed for domains already in the profile.
Every `dig`, `getaddrinfo`, or HTTP request that triggers a DNS lookup inside
the container adds the resolved IPs to `t40_project_allow_v4`/`t40_project_allow_v6`
automatically.

To watch the sets grow in real time:

```bash
watch terok-shield rules my-container
```

!!! note "Future modes"
    Additional modes for different network topologies may be added in the future.
