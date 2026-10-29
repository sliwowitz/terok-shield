# Audit Logging

terok-shield logs firewall events at two levels: application-level JSON-lines
logs and kernel-level per-packet nftables logs.

## Application logs (JSON-lines)

Each container has its own audit log at `{state_dir}/audit.jsonl` (e.g.
`~/.local/state/terok/shield/containers/my-container/audit.jsonl`).

Each line is a JSON object:

```json
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "ruleset applied"}
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "read 3 cached IPs"}
{"ts": "2026-03-07T12:00:00+00:00", "container": "my-container", "action": "setup", "detail": "verification passed"}
```

### Actions

| Action | Meaning |
|--------|---------|
| `setup` | Firewall setup step (ruleset applied, IPs loaded, verification) |
| `allowed` | Domain/IP added to allow set at runtime (`detail` says `at next start` when the container was stopped and the allow was recorded for its next start) |
| `allow_refused` | Allow refused because the security tier denies the target (`dest` is the shared address when that was the cause; break-glass only) |
| `denied` | Domain/IP removed from allow set at runtime |
| `shield_down` | Container switched to the DOWN posture |
| `shield_up` | Container restored to deny-all mode |
| `bypass_armed` | Timed allow-all window opened (`detail` carries the duration) |
| `bypass_disarmed` | Timed allow-all window closed before its timeout |
| `override` | Break-glass granted on a running container (`dest` is the target; `detail` carries `expires=` and the `reason`) |
| `override_revoked` | Break-glass revoked before its expiry, written once no running ruleset holds it (`dest` is the target; `detail` repeats the grant's `expires=` and `reason`, plus `at next start` when the container was stopped). Not written when nft could not drop the override from the running ruleset — the revoke then fails with an error |
| `override_expired` | An authored t10 override had already run out, so it was not applied (`detail` carries `expires=`) |
| `override_range` | A t10 override opens a whole CIDR above the security tier (`detail` is the range) |
| `note` | Names the container's DNS tier pins to the addresses they resolved to, one line per kind — allowlisted, break-glass, denied — worded for the posture. Written at launch and restart, on `shield up` (every kind) and on a plain `shield down` (denied names only); see [Pinned names](modes.md#pinned-names-and-the-rotation-warning) |
| `error` | Something failed |

A `note` is a record, not the warning itself: with audit disabled there is no
`note`, yet the CLI verbs still print the same lines to stderr, and
`recorded_rotation_risk` computes them from the bundle on demand.

The NFLOG reader adds one line per destination per 30 seconds for what the
workload's own traffic met. These lines carry `dest`, `port` and `proto` (and
`domain` when the reader recovered one from the dnsmasq log), and they are
what [`harvest`](cli.md#harvest) reads back:

| Action | Meaning |
|--------|---------|
| `blocked` | Refused by the terminal rule — the one action that also raises a clearance prompt |
| `bypass` | Accepted through the open timed window |
| `down` | Accepted only because the shield is down — the UP posture would have refused it |
| `security_deny` | Refused by the t20 deny set: the security tier (vault-relayed hosts) or the operator's runtime deny |
| `private_range` | Refused by a range floor: the hard-deny floor (link-local, IMDS) or a private range (RFC 1918, RFC 4193) |

Accepts by the allow tiers are not recorded: they are the bulk of all
traffic, and the kernel log keeps them (`TEROK_SHIELD_ALLOWED`) for anyone who
wants them. Neither is the kernel's own IPv6 chatter: link-local multicast,
and neighbour discovery to link-local addresses.

### Viewing logs

```bash
# Last 10 entries for a specific container
terok-shield logs --container my-container -n 10

# Last 5 entries across all containers
terok-shield logs -n 5
```

### Detail prefixes

Lines prefixed with `[ips]` contain full IP lists and can be filtered out
by log readers that only need summaries:

```json
{"action": "setup", "detail": "[ips] cached: 1.1.1.1, 1.0.0.1, 10.0.0.5"}
{"action": "setup", "detail": "[ips] added to allow sets: 1.1.1.1, 1.0.0.1"}
```

## Kernel packet logs

nftables rules generate per-packet entries in dmesg/journald using log
prefixes:

| Prefix | Meaning |
|--------|---------|
| `TEROK_SHIELD_ALLOWED:` | New connection accepted by an allow tier — t10 override, t30 provider, t40 project — in any posture (not rate-limited; established traffic is accepted earlier in the chain and not logged) |
| `TEROK_SHIELD_DENIED:` | Packet rejected by the t20 deny set: the security tier (vault-relayed provider hosts) and the operator's runtime denies |
| `TEROK_SHIELD_PRIVATE:` | Packet rejected by a range floor: the hard-deny floor (IPv4 link-local including IMDS, IPv6 link-local, the AWS IPv6 IMDS, and under slirp4netns the gateway — the host's own loopback — past the ports the preamble opens) or a private range (RFC 1918, RFC 4193) |
| `TEROK_SHIELD_BLOCKED:` | Packet rejected by the terminal default-deny rule (unclassified), or dropped in quarantine |
| `TEROK_SHIELD_BYPASS:` | Packet accepted through the timed bypass window |
| `TEROK_SHIELD_DOWN:` | New connection accepted only because the shield is down (DOWN or DISENGAGED posture) — the allow tiers log `ALLOWED` ahead of it, so this is what UP would have refused |

View with:

```bash
journalctl -k --grep TEROK_SHIELD
```

## Disabling audit logging

In `~/.config/terok/shield/config.yml`:

```yaml
audit:
  enabled: false
```

This disables all application-level logging. A container keeps the choice it
was created with: `pre_start` records it in the state bundle
(`audit.enabled`), and the container's NFLOG reader honours it, writing no
lines at all — the clearance prompts still flow. `harvest` reports such a
container as having audit disabled rather than as having nothing to harvest.
Kernel packet logs are controlled by the nftables ruleset and remain active
regardless.
