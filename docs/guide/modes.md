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

1. `Shield.pre_start()` installs the OCI hooks (see
   [Per-container state bundle](#per-container-state-bundle) for where they
   land), processes the allowlist profiles, and pre-generates the complete nft
   ruleset to `ruleset.nft`. DNS handling differs by tier:
   - **dnsmasq tier**: no pre-resolution at all — the composed policy lands in
     `policy/40-project-allow`, literal IP entries seed the allow sets via the
     generated ruleset, and dnsmasq `--nftset` populates the sets at runtime,
     per DNS query, *before* the answer reaches the workload. Launch cost stays
     O(1) in allowlist size and CDN rotation is tracked for free.
   - **dig / getent tier**: all entries (domains and raw IPs) are statically
     resolved at pre-start time into the `resolved.ips` cache; no runtime
     resolution or rotation tracking.

   Returns podman args with OCI annotations (`state_dir`, `loopback_ports`,
   `version`, `upstream_dns`, `dns_tier`)
2. When podman creates a container with the `terok.shield.profiles` annotation,
   it fires the stdlib-only hook script at the `createRuntime` stage
3. The hook reads `state_dir` from annotations and applies the pre-generated
   `ruleset.nft` (gateway addresses already baked in at `pre_start`) inside the
   container's network namespace via `nsenter`, then starts a per-container
   dnsmasq instance if the dnsmasq tier is active
4. dnsmasq runs inside the container's network namespace with `--nftset` pointing
   to the `t40_project_allow_v4`/`t40_project_allow_v6` sets — every DNS resolution
   automatically adds the resolved IPs to the live nft project-allow sets
5. The workload starts with `CAP_NET_ADMIN` and `CAP_NET_RAW` dropped, so it
   cannot modify the rules

### Chain evaluation order

```text
preamble (lo, established, DNS, infra ports, +localhost grants) → t00 hard-deny (link-local + IMDS) → t10 override → t20 security-deny (@t20_security_deny + RFC1918/RFC4193) → t30 provider allow → t40 project allow → bypass window → terminal reject (log BLOCKED)
```

### When to use

- Single containers or small deployments
- When you want per-container isolation (each container has its own firewall)
- Simplest setup — just needs `nft` binary

### Per-container state bundle

Each container's hooks and state are isolated in its own directory:

```text
{state_dir}/
├── hooks/                                  # OCI hook descriptors (only if per-container hooks are supported)
├── terok-shield-hook                       # Hook entrypoint (stdlib-only Python), per-container hooks only
├── policy/                                 # v15 tiered +/- policy, one file per tier set
│   ├── 10-override                         #   → nft set t10_override (break-glass allow)
│   ├── 20-security-deny                    #   → nft set t20_security_deny (vault hosts + operator deny)
│   ├── 30-provider-allow                   #   → nft set t30_provider_allow (provider egress)
│   ├── 40-project-allow                    #   → nft set t40_project_allow (project allowlist)
│   └── live                                #   Runtime allow/deny overlay (+/- lines)
├── resolved.ips                            # Resolved allow IPs (t40 seed; dig/getent tiers)
├── ruleset.nft                             # Pre-generated nft ruleset (gateways baked in)
├── dnsmasq.conf                            # Generated dnsmasq config (dnsmasq tier)
├── dnsmasq.pid                             # dnsmasq PID (dnsmasq tier)
├── resolv.conf                             # Bind-mounted /etc/resolv.conf (dnsmasq tier)
├── upstream.dns                            # Persisted upstream DNS address
├── dns.tier                                # Persisted active DNS tier
└── audit.jsonl                             # Per-container audit log
```

> **Where the hooks live.** The `hooks/` descriptors and the
> `terok-shield-hook` entrypoint above are part of this per-container bundle
> only when podman supports persistent per-container hooks. It does not today —
> podman drops a per-container `--hooks-dir` across stop/start
> ([containers/podman#17935](https://github.com/containers/podman/issues/17935)) —
> so shield installs the hooks once into a **global** directory and registers it
> in podman's `containers.conf` (`hooks_dir` under `[engine]`;
> `~/.config/containers/containers.conf` for rootless). Run `terok-shield setup`
> to install the global hooks and patch `containers.conf`. Everything else in
> the bundle stays per-container.

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

When dnsmasq is active, the allow sets are populated dynamically — no manual
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
