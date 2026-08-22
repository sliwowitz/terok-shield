# AppArmor & the dnsmasq DNS tier

shield's most user-friendly DNS-egress mode runs a per-container **dnsmasq** that
auto-populates the nft allow sets from live DNS replies (the `dnsmasq`
tier — it handles domains with rotating IPs). That dnsmasq reads its
config and writes its pid/log under the per-task shield state directory
in your home (`~/.local/share/terok/.../shield/`).

## On AppArmor-enforcing hosts

Distributions that ship an **enforcing AppArmor profile for
`/usr/sbin/dnsmasq`** (Manjaro, and anywhere the [`apparmor.d`][1]
profile set is installed) confine dnsmasq to the conventional server
paths and forbid your home directory, so the confined dnsmasq is denied
reading its config there.

shield handles this automatically: at pre-start it probes whether a
confined dnsmasq can read the state dir (running `dnsmasq --test` — no
root needed) and, if not, **falls back to the `dig` tier**. Egress
filtering stays fully enforced, and DNS keeps working. Shield still owns the
container's `resolv.conf` on the fallback tiers. It points `resolv.conf` at
the upstream forwarder the firewall allows, instead of podman's default.
Podman's default lists the host's own nameservers. On a LAN one of those is a
router, and the egress filter blocks the router as a private range. Only the
*live* handling changes: on the fallback tiers domain allowlists resolve once
at pre-start, not as each reply arrives.

The fallback is **not silent**. Shield logs it at `WARNING` on the console,
with this remedy, and in the per-container audit log. A later egress failure
from a rotated address then traces back to a known cause.

## Keeping the dnsmasq tier

[terok-sandbox](https://github.com/terok-ai/terok-sandbox) provides an [apparmor profile installer](https://github.com/terok-ai/terok-sandbox/blob/master/src/terok_sandbox/resources/apparmor/install_profile.sh). It needs to know the configured state root directory (by default `$HOME/.local/share/terok`). If you use the [terok](https://github.com/terok-ai/terok) orchestrator, `terok setup` will
point you to the right script to launch.

## If you can't install the profile

The automatic `dig` fallback keeps you working unprivileged; no action
needed. shield does not bypass the profile (e.g. by running dnsmasq
unconfined), as that would override a policy the host administrator set.


[1]: https://github.com/roddhjav/apparmor.d
