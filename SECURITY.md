# Security Policy

## Scope of this tool

NoxGuardian performs **active** network scanning. It sends ARP requests, TCP
connections and nmap service probes. It is not passive and makes no attempt to
be stealthy. Its intended use is monitoring a network you own.

Scanning networks without authorisation is illegal in most jurisdictions. Use it
on your own LAN, or with explicit written permission from the network owner.

---

## Data sensitivity

The files NoxGuardian produces are sensitive. A single report contains:

- Every MAC address on the network, and the hardware vendor of each device
- Hostnames, current and historical IP addresses
- **A behavioural timeline**: when each device arrives, when it leaves, and how
  long it stays. On a home network this maps directly onto the movements of the
  people living there.
- Open ports and service versions, which is an inventory of exploitable surface

Treat `noxguardian_events.log`, `noxguardian_state.json` and the generated
`.xlsx` files as you would any personal data.

- The repository `.gitignore` excludes them. **Do not commit them.**
- Redact MAC addresses, hostnames and IPs before attaching output to an issue.
- Consider the legal position in your jurisdiction before monitoring a network
  used by other people, including family members and guests.

---

## Reporting a vulnerability

If you find a security issue in NoxGuardian itself, please **do not open a
public issue**.

Report it privately through GitHub's
[security advisory](https://github.com/nostraxiten/NoxGuardian/security/advisories/new)
form.

Please include:

- A description of the issue and its impact
- Steps to reproduce
- The affected version and your platform

You can expect an initial response within a few days. Fixes are released as a
patch version with the issue credited unless you prefer otherwise.

---

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

---

## Known operational considerations

These are properties of the design, not vulnerabilities:

- **Running as root is the recommended mode.** ARP sweeps require raw sockets.
  If you prefer not to run the whole process as root, grant the capability to
  nmap alone and run NoxGuardian unprivileged:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
  ```

- **`-sV` version probing is noisy.** The deep scan sends real service probes
  and will appear in the logs of anything that keeps them. Intrusion detection
  systems on the network will flag it.

- **Checkpoints are written with the permissions of the running user.** When run
  under `sudo`, output files are owned by root and readable only by root by
  default. This is intentional, given what they contain.
