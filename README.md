# 🦉 OLateral

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OLateral** — Lateral-movement mapper — SMB/WMI/WinRM/SSH/PtH reachability & checklist ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OLateral — Lateral-movement mapper — SMB/WMI/WinRM/SSH/PtH reachability & checklist. Lateral-movement mapper (SMB/WMI/WinRM/SSH/PtH). Map lateral techniques, reachability graph, requirement checklist.

---

## ✨ Features

- Map lateral-movement reachability across SMB/WMI/WinRM/SSH/PtH paths
- Produce operator checklists for authorized purple-team scenarios
- Highlight likely pivots and authentication surfaces
- Non-destructive planning emphasis with explicit authorization posture
- Structured graph-friendly findings
- Export movement maps for engagement notes

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OLateral OLateral.go
./OLateral --help
./OLateral --target 192.168.1.0/24
./OLateral --input hosts.txt --format json
./OLateral --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
