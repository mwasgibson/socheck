# Socheck

**Socheck** is a Zero-Trust Security Operations Center (SOC) dashboard. It simulates enterprise 802.1X/RADIUS access control, real-time Isolation Forest anomaly detection on network telemetry, automated multi-vendor switch quarantine via Netmiko-style orchestration (Cisco IOS-XE, Juniper Junos, Arista EOS), audit trails, and disaster recovery drills.

Repository: [mwasgibson/socheck](https://github.com/mwasgibson/socheck)

---

## Features

| Area | What you get |
|------|----------------|
| **SOC Overview** | KPI strip, attack simulator, live telemetry table, recent Netmiko mitigations |
| **Fleet Topology** | Multi-vendor switch fabric, per-port 802.1X state, quarantine / restore |
| **ML Detector** | Isolation Forest (100 trees, ψ=256), score threshold ~0.62, precision/recall, recalibrate |
| **Netmiko Terminal** | Vendor-specific CLI quarantine scripts and simulated terminal playback |
| **Audit Logs** | Severity-filtered events with MITRE tags; CEF / Syslog-style export helpers |
| **Disaster Recovery** | Encrypted-style JSON snapshots with checksums and one-click rollback drills |
| **RBAC** | Super Admin · SecOps Analyst · Network Auditor role switcher |

**Attack vectors (MITRE-mapped):** 802.1X bypass (T1078), ARP spoof (T1557), MAC clone (T1036), C2 beacon (T1071).

---

## Stack

- React 19 + TypeScript  
- Tailwind CSS v4  
- lucide-react  
- Vite 8  

Fully client-side. No backend or API keys required.

---

## Quick start

```bash
git clone https://github.com/mwasgibson/socheck.git
cd socheck
npm install
npm run dev            # http://localhost:3000
```

Build:

```bash
npm run build
npm run preview
```

---

## Project layout

```
├── src/
│   ├── components/     # TopBar, KPI strip, attack simulator, topology, ML, Netmiko, audit, DR
│   ├── services/       # Isolation Forest, Netmiko orchestrator, network state store
│   ├── types/          # Switches, ports, telemetry, jobs, audit, snapshots
│   ├── App.tsx
│   └── main.tsx
├── index.html
├── package.json        # name: socheck @ 0.1.0
└── vite.config.ts
```

---

## How it works

1. **Telemetry** — 6-D feature vectors (packet length, entropy, SYN/ACK ratio, jitter, burst velocity, destination dispersion).
2. **Isolation Forest** — Path-length anomaly scores; threshold 0.62 triggers quarantine.
3. **Netmiko simulation** — Vendor drivers emit realistic CLI (VLAN 99 isolation + drop ACL) and terminal logs.
4. **DR** — Snapshots serialize switch/port state with a content checksum for restore drills.

This is a **demo / training** orchestrator: all switches, credentials, and mitigations are in-browser simulations. Do not point it at production gear without a real Netmiko backend.

---

## License

MIT (or project default). See repository settings.
