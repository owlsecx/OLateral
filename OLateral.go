// OLateral — Lateral-movement mapper (SMB/WMI/WinRM/SSH/PtH).
// Author: khaled.s.haddad   Website: owlsec.org   Language: Go (stdlib only)
// Map lateral techniques, reachability graph, requirement checklist.
// AUTHORIZED TESTING ONLY. MITRE ATT&CK TA0008 (Lateral Movement).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
	DR  = "\033[96m" // legacy frame alias → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func line(w int)       { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", B, R) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

const BANNER = `
 ██████╗ ██╗      █████╗ ████████╗███████╗██████╗  █████╗ ██╗     
██╔═══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║     
██║   ██║██║     ███████║   ██║   █████╗  ██████╔╝███████║██║     
██║   ██║██║     ██╔══██║   ██║   ██╔══╝  ██╔══██╗██╔══██║██║     
╚██████╔╝███████╗██║  ██║   ██║   ███████╗██║  ██║██║  ██║███████╗
 ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
`

const APPNAME = "OLateral"
const SUITE = "Owl Offensive Suite"
const TAGLINE = "Lateral-movement mapper — SMB/WMI/WinRM/SSH/PtH reachability & checklist"
const SUBLINE = "SMB · WMI · WinRM · RDP · SSH · DCOM · PtH/PtT · relay · ADCS · cloud"
const VERSION = "2.2.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const PRIMARY_MITRE = "TA0008"

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW) + col("   ·   MITRE "+PRIMARY_MITRE, DIM))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Printf("  %s  %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col("[H]", YLW+B) + "  " + col("Help & Usage", W) + col("  — how to use, options, CLI flags & examples", DIM))
	fmt.Println("  " + col("[0]", R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ====================================================================
//  DOMAIN MODEL
// ====================================================================

// CatalogEntry is a single technique / binary / mechanism / channel
// record in this tool's knowledge base. It is the unit that powers
// the catalog browser, the marker scanner, the planner and exports.
type CatalogEntry struct {
	ID        string
	Name      string
	Category  string
	Platform  string
	Tactic    string
	Technique string
	Severity  string
	Summary   string
	Detail    string
	Commands  []string
	Markers   []string
	Detection []string
	Refs      []string
	Tags      []string
}

// Finding is a single observation produced by scanning an input, by a
// planner, or by a configuration audit. Findings carry MITRE mapping,
// severity and evidence and feed every export format.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Score     int      `json:"score"`
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Detection string   `json:"detection,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	Fprint    string   `json:"fingerprint"`
}

// Report bundles a full analysis run for export and grading.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Tagline    string    `json:"tagline"`
	Generated  string    `json:"generated"`
	Target     string    `json:"target,omitempty"`
	Mode       string    `json:"mode"`
	Findings   []Finding `json:"findings"`
	Grade      string    `json:"grade"`
	Score      int       `json:"score"`
	Summary    string    `json:"summary"`
	MitrePrime string    `json:"mitrePrimary"`
}

// severity ordering / weights
var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
var sevWeight = map[string]int{"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return R + B
	case "high":
		return R
	case "medium":
		return YLW
	case "low":
		return GRN
	default:
		return GY
	}
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// ====================================================================
//  CATALOG (tool-specific knowledge base)
// ====================================================================

var catalog = []CatalogEntry{
	{
		ID: "LAT-SMB", Name: "SMB lateral (PsExec/smbexec)", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.002", Severity: "high",
		Summary:   "Remote service create over SMB.",
		Detail:    "Remote service create over SMB. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SMB lateral (PsExec/smbexec)", "# MITRE T1021.002"},
		Markers:   []string{"psexec|smbexec|services\\.exe.*cmd"},
		Detection: []string{"Hunt markers of SMB lateral (PsExec/smbexec)", "Map to T1021.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-WMI", Name: "WMI lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1047", Severity: "high",
		Summary:   "wmic / Invoke-WmiMethod remote exec.",
		Detail:    "wmic / Invoke-WmiMethod remote exec. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WMI lateral", "# MITRE T1047"},
		Markers:   []string{"Invoke-WmiMethod|wmic\\s+/node:", "Win32_Process.*Create"},
		Detection: []string{"Hunt markers of WMI lateral", "Map to T1047", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1047"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-WINRM", Name: "WinRM / PSRemoting", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.006", Severity: "high",
		Summary:   "Enter-PSSession / Invoke-Command.",
		Detail:    "Enter-PSSession / Invoke-Command. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WinRM / PSRemoting", "# MITRE T1021.006"},
		Markers:   []string{"Enter-PSSession|Invoke-Command\\s+-ComputerName", "winrm\\s+"},
		Detection: []string{"Hunt markers of WinRM / PSRemoting", "Map to T1021.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.006"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-RDP", Name: "RDP lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.001", Severity: "medium",
		Summary:   "Interactive RDP to next host.",
		Detail:    "Interactive RDP to next host. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# RDP lateral", "# MITRE T1021.001"},
		Markers:   []string{"mstsc|xfreerdp|rdesktop|\\bRDP\\b"},
		Detection: []string{"Hunt markers of RDP lateral", "Map to T1021.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SSH", Name: "SSH lateral", Category: "Lateral", Platform: "linux",
		Tactic: "TA0008", Technique: "T1021.004", Severity: "medium",
		Summary:   "SSH hop with key/password.",
		Detail:    "SSH hop with key/password. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SSH lateral", "# MITRE T1021.004"},
		Markers:   []string{"ssh\\s+\\w+@|scp\\s+"},
		Detection: []string{"Hunt markers of SSH lateral", "Map to T1021.004", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.004"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-DCOM", Name: "DCOM lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.003", Severity: "high",
		Summary:   "MMC/ShellWindows/ShellBrowserWindow DCOM.",
		Detail:    "MMC/ShellWindows/ShellBrowserWindow DCOM. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DCOM lateral", "# MITRE T1021.003"},
		Markers:   []string{"DCOM|MMC20\\.Application|ShellWindows"},
		Detection: []string{"Hunt markers of DCOM lateral", "Map to T1021.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.003"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-PTH", Name: "Pass-the-Hash", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1550.002", Severity: "critical",
		Summary:   "NTLM hash reuse for lateral.",
		Detail:    "NTLM hash reuse for lateral. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Pass-the-Hash", "# MITRE T1550.002"},
		Markers:   []string{"pass.?the.?hash|\\bPtH\\b|sekurlsa::pth|aes256.?hash"},
		Detection: []string{"Hunt markers of Pass-the-Hash", "Map to T1550.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1550.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-PTT", Name: "Pass-the-Ticket", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1550.003", Severity: "critical",
		Summary:   "Kerberos TGT/TGS reuse.",
		Detail:    "Kerberos TGT/TGS reuse. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Pass-the-Ticket", "# MITRE T1550.003"},
		Markers:   []string{"pass.?the.?ticket|\\bPtT\\b|kirbi|Rubeus.*(ptt|asktgt)"},
		Detection: []string{"Hunt markers of Pass-the-Ticket", "Map to T1550.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1550.003"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-OVERPS", Name: "Over-Pass-the-Hash", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1550.002", Severity: "high",
		Summary:   "Hash -> TGT via Kerberos.",
		Detail:    "Hash -> TGT via Kerberos. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Over-Pass-the-Hash", "# MITRE T1550.002"},
		Markers:   []string{"over.?pass.?the.?hash|Rubeus.*asktgt.*/rc4"},
		Detection: []string{"Hunt markers of Over-Pass-the-Hash", "Map to T1550.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1550.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SC", Name: "sc remote service", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1543.003", Severity: "high",
		Summary:   "sc \\\\host create/start.",
		Detail:    "sc \\\\host create/start. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# sc remote service", "# MITRE T1543.003"},
		Markers:   []string{"sc\\s+\\\\\\\\\\\\\\\\", "CreateService"},
		Detection: []string{"Hunt markers of sc remote service", "Map to T1543.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1543.003"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SCHTASKS", Name: "Remote scheduled task", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1053.005", Severity: "high",
		Summary:   "schtasks /S remote.",
		Detail:    "schtasks /S remote. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Remote scheduled task", "# MITRE T1053.005"},
		Markers:   []string{"schtasks\\s+/S\\s+", "Register-ScheduledTask.*-CimSession"},
		Detection: []string{"Hunt markers of Remote scheduled task", "Map to T1053.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1053.005"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-AT", Name: "Remote at job", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1053.002", Severity: "low",
		Summary:   "Legacy at \\\\host.",
		Detail:    "Legacy at \\\\host. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Remote at job", "# MITRE T1053.002"},
		Markers:   []string{"\\bat\\s+\\\\\\\\\\\\\\\\"},
		Detection: []string{"Hunt markers of Remote at job", "Map to T1053.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1053.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-WINRS", Name: "winrs remote shell", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.006", Severity: "medium",
		Summary:   "winrs -r:host.",
		Detail:    "winrs -r:host. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# winrs remote shell", "# MITRE T1021.006"},
		Markers:   []string{"winrs\\s+-r:"},
		Detection: []string{"Hunt markers of winrs remote shell", "Map to T1021.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.006"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SMBEXEC", Name: "smbexec / atexec", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.002", Severity: "high",
		Summary:   "Impacket smbexec/atexec style.",
		Detail:    "Impacket smbexec/atexec style. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# smbexec / atexec", "# MITRE T1021.002"},
		Markers:   []string{"smbexec|atexec|impacket"},
		Detection: []string{"Hunt markers of smbexec / atexec", "Map to T1021.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-WMIEXEC", Name: "wmiexec", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1047", Severity: "high",
		Summary:   "Impacket wmiexec.",
		Detail:    "Impacket wmiexec. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# wmiexec", "# MITRE T1047"},
		Markers:   []string{"wmiexec"},
		Detection: []string{"Hunt markers of wmiexec", "Map to T1047", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1047"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-PSREMOTE", Name: "PowerShell remoting fan-out", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.006", Severity: "medium",
		Summary:   "Invoke-Command -ComputerName (list).",
		Detail:    "Invoke-Command -ComputerName (list). For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# PowerShell remoting fan-out", "# MITRE T1021.006"},
		Markers:   []string{"Invoke-Command\\s+-ComputerName\\s+\\("},
		Detection: []string{"Hunt markers of PowerShell remoting fan-out", "Map to T1021.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.006"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-ADMINSHARE", Name: "Admin share copy+exec", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.002", Severity: "high",
		Summary:   "Copy to ADMIN$/C$ then remote exec.",
		Detail:    "Copy to ADMIN$/C$ then remote exec. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Admin share copy+exec", "# MITRE T1021.002"},
		Markers:   []string{"\\\\\\\\\\\\\\\\[^\\\\\\\\]+\\\\\\\\(ADMIN\\$|C\\$)", "copy\\s+.*\\\\\\\\\\\\\\\\"},
		Detection: []string{"Hunt markers of Admin share copy+exec", "Map to T1021.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-GPO", Name: "GPO immediate task lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1484.001", Severity: "critical",
		Summary:   "Push immediate scheduled task via GPO.",
		Detail:    "Push immediate scheduled task via GPO. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# GPO immediate task lateral", "# MITRE T1484.001"},
		Markers:   []string{"Immediate.?Task|GPO.*schtask"},
		Detection: []string{"Hunt markers of GPO immediate task lateral", "Map to T1484.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1484.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-MSSQL", Name: "MSSQL linked server / xp_cmdshell", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1505.001", Severity: "high",
		Summary:   "Linked server hop or xp_cmdshell.",
		Detail:    "Linked server hop or xp_cmdshell. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# MSSQL linked server / xp_cmdshell", "# MITRE T1505.001"},
		Markers:   []string{"xp_cmdshell|OPENQUERY|linked.?server"},
		Detection: []string{"Hunt markers of MSSQL linked server / xp_cmdshell", "Map to T1505.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1505.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-DCOM-SHELL", Name: "DCOM ShellBrowserWindow", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.003", Severity: "high",
		Summary:   "ShellBrowserWindow.Document.Application.Service.",
		Detail:    "ShellBrowserWindow.Document.Application.Service. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DCOM ShellBrowserWindow", "# MITRE T1021.003"},
		Markers:   []string{"ShellBrowserWindow|ShellWindows"},
		Detection: []string{"Hunt markers of DCOM ShellBrowserWindow", "Map to T1021.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.003"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-RDP-HIJACK", Name: "RDP session hijack", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1563.002", Severity: "high",
		Summary:   "tscon session hijack as SYSTEM.",
		Detail:    "tscon session hijack as SYSTEM. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# RDP session hijack", "# MITRE T1563.002"},
		Markers:   []string{"tscon\\s+\\d+", "session.?hijack"},
		Detection: []string{"Hunt markers of RDP session hijack", "Map to T1563.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1563.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SSH-AGENT", Name: "SSH agent forwarding abuse", Category: "Lateral", Platform: "linux",
		Tactic: "TA0008", Technique: "T1550", Severity: "medium",
		Summary:   "Abuse forwarded agent to hop.",
		Detail:    "Abuse forwarded agent to hop. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SSH agent forwarding abuse", "# MITRE T1550"},
		Markers:   []string{"SSH_AUTH_SOCK|ForwardAgent"},
		Detection: []string{"Hunt markers of SSH agent forwarding abuse", "Map to T1550", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1550"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-KERBEROS", Name: "Kerberos delegation lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1550.003", Severity: "high",
		Summary:   "S4U2Proxy / constrained delegation hop.",
		Detail:    "S4U2Proxy / constrained delegation hop. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Kerberos delegation lateral", "# MITRE T1550.003"},
		Markers:   []string{"S4U2Proxy|S4U2Self|constrained.?delegation"},
		Detection: []string{"Hunt markers of Kerberos delegation lateral", "Map to T1550.003", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1550.003"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-CERT", Name: "ADCS certificate lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1649", Severity: "high",
		Summary:   "ESC1/ESC8 cert -> auth as other user.",
		Detail:    "ESC1/ESC8 cert -> auth as other user. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# ADCS certificate lateral", "# MITRE T1649"},
		Markers:   []string{"ESC[18]\\b|certipy|ADCS"},
		Detection: []string{"Hunt markers of ADCS certificate lateral", "Map to T1649", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1649"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-RELAY", Name: "NTLM relay lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1557.001", Severity: "critical",
		Summary:   "ntlmrelayx to SMB/LDAP/HTTP.",
		Detail:    "ntlmrelayx to SMB/LDAP/HTTP. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# NTLM relay lateral", "# MITRE T1557.001"},
		Markers:   []string{"ntlmrelayx|coerce|PrinterBug|PetitPotam"},
		Detection: []string{"Hunt markers of NTLM relay lateral", "Map to T1557.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1557.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-COERCE", Name: "Auth coerce (PetitPotam etc)", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1187", Severity: "high",
		Summary:   "Force auth to attacker listener.",
		Detail:    "Force auth to attacker listener. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Auth coerce (PetitPotam etc)", "# MITRE T1187"},
		Markers:   []string{"PetitPotam|PrinterBug|DFSCoerce|SpoolSample"},
		Detection: []string{"Hunt markers of Auth coerce (PetitPotam etc)", "Map to T1187", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1187"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-GOLDEN", Name: "Golden ticket lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1558.001", Severity: "critical",
		Summary:   "Forged TGT for domain-wide access.",
		Detail:    "Forged TGT for domain-wide access. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Golden ticket lateral", "# MITRE T1558.001"},
		Markers:   []string{"golden.?ticket|kerberos::golden"},
		Detection: []string{"Hunt markers of Golden ticket lateral", "Map to T1558.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1558.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SILVER", Name: "Silver ticket lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1558.002", Severity: "critical",
		Summary:   "Forged service ticket.",
		Detail:    "Forged service ticket. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Silver ticket lateral", "# MITRE T1558.002"},
		Markers:   []string{"silver.?ticket|kerberos::silver"},
		Detection: []string{"Hunt markers of Silver ticket lateral", "Map to T1558.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1558.002"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-DCCS", Name: "DCC / cached cred reuse", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1003.005", Severity: "medium",
		Summary:   "Cached domain creds for offline crack/reuse.",
		Detail:    "Cached domain creds for offline crack/reuse. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DCC / cached cred reuse", "# MITRE T1003.005"},
		Markers:   []string{"DCC2|msv:|cached.?credential"},
		Detection: []string{"Hunt markers of DCC / cached cred reuse", "Map to T1003.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1003.005"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-BROWSER", Name: "Browser session cookie steal", Category: "Lateral", Platform: "cross",
		Tactic: "TA0008", Technique: "T1539", Severity: "medium",
		Summary:   "Steal cookies for SaaS lateral.",
		Detail:    "Steal cookies for SaaS lateral. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Browser session cookie steal", "# MITRE T1539"},
		Markers:   []string{"cookie.?steal|session.?token"},
		Detection: []string{"Hunt markers of Browser session cookie steal", "Map to T1539", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1539"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-CLOUD", Name: "Cloud IAM lateral", Category: "Lateral", Platform: "cross",
		Tactic: "TA0008", Technique: "T1021", Severity: "high",
		Summary:   "AWS/Azure/GCP role assumption hop.",
		Detail:    "AWS/Azure/GCP role assumption hop. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Cloud IAM lateral", "# MITRE T1021"},
		Markers:   []string{"sts:AssumeRole|az\\s+account|gcloud\\s+auth"},
		Detection: []string{"Hunt markers of Cloud IAM lateral", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-K8S", Name: "Kubernetes lateral", Category: "Lateral", Platform: "linux",
		Tactic: "TA0008", Technique: "T1021", Severity: "high",
		Summary:   "SA token -> other namespace/node.",
		Detail:    "SA token -> other namespace/node. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Kubernetes lateral", "# MITRE T1021"},
		Markers:   []string{"kubectl\\s+auth|serviceaccount"},
		Detection: []string{"Hunt markers of Kubernetes lateral", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SSH-KEYSPRAY", Name: "SSH key reuse spray", Category: "Lateral", Platform: "linux",
		Tactic: "TA0008", Technique: "T1078", Severity: "medium",
		Summary:   "Stolen key tried across fleet.",
		Detail:    "Stolen key tried across fleet. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SSH key reuse spray", "# MITRE T1078"},
		Markers:   []string{"ssh.*-i\\s+.*id_rsa"},
		Detection: []string{"Hunt markers of SSH key reuse spray", "Map to T1078", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1078"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-PASSWORD", Name: "Password reuse lateral", Category: "Lateral", Platform: "cross",
		Tactic: "TA0008", Technique: "T1078", Severity: "high",
		Summary:   "Same local admin password across hosts.",
		Detail:    "Same local admin password across hosts. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Password reuse lateral", "# MITRE T1078"},
		Markers:   []string{"password.?reuse|local.?admin.?password"},
		Detection: []string{"Hunt markers of Password reuse lateral", "Map to T1078", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1078"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-LAPS", Name: "LAPS read then lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1078", Severity: "medium",
		Summary:   "Read LAPS then RDP/SMB as local admin.",
		Detail:    "Read LAPS then RDP/SMB as local admin. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# LAPS read then lateral", "# MITRE T1078"},
		Markers:   []string{"ms-Mcs-AdmPwd|Get-LapsADPassword"},
		Detection: []string{"Hunt markers of LAPS read then lateral", "Map to T1078", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1078"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-MAP", Name: "Reachability map", Category: "Lateral", Platform: "cross",
		Tactic: "TA0007", Technique: "T1018", Severity: "info",
		Summary:   "Host-to-host reachability for planning.",
		Detail:    "Host-to-host reachability for planning. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Reachability map", "# MITRE T1018"},
		Markers:   []string{"reachability|lateral.?map"},
		Detection: []string{"Hunt markers of Reachability map", "Map to T1018", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1018"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-REQ", Name: "Requirement checklist", Category: "Lateral", Platform: "cross",
		Tactic: "TA0008", Technique: "T1021", Severity: "info",
		Summary:   "Creds/ports/rights needed per technique.",
		Detail:    "Creds/ports/rights needed per technique. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Requirement checklist", "# MITRE T1021"},
		Markers:   []string{"requirement|prereq|checklist"},
		Detection: []string{"Hunt markers of Requirement checklist", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-DETECT", Name: "Lateral detection notes", Category: "Lateral", Platform: "cross",
		Tactic: "TA0008", Technique: "T1021", Severity: "info",
		Summary:   "Defensive telemetry for each technique.",
		Detail:    "Defensive telemetry for each technique. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Lateral detection notes", "# MITRE T1021"},
		Markers:   []string{"lateral.?detect|telemetry"},
		Detection: []string{"Hunt markers of Lateral detection notes", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-TIER", Name: "Tier admin model break", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1078", Severity: "high",
		Summary:   "Tier0/1/2 boundary crossed.",
		Detail:    "Tier0/1/2 boundary crossed. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Tier admin model break", "# MITRE T1078"},
		Markers:   []string{"tier\\s*[012]|Enterprise Access Model"},
		Detection: []string{"Hunt markers of Tier admin model break", "Map to T1078", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1078"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-JEAbreak", Name: "JEA breakout lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021.006", Severity: "medium",
		Summary:   "Escape constrained JEA endpoint.",
		Detail:    "Escape constrained JEA endpoint. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# JEA breakout lateral", "# MITRE T1021.006"},
		Markers:   []string{"JEA|Just.?Enough.?Admin"},
		Detection: []string{"Hunt markers of JEA breakout lateral", "Map to T1021.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021.006"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-SMB-SIGN", Name: "SMB signing disabled enables relay", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1557.001", Severity: "high",
		Summary:   "SMB signing not required.",
		Detail:    "SMB signing not required. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SMB signing disabled enables relay", "# MITRE T1557.001"},
		Markers:   []string{"EnableSecuritySignature\\s*=\\s*0|RequireSecuritySignature\\s*=\\s*0"},
		Detection: []string{"Hunt markers of SMB signing disabled enables relay", "Map to T1557.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1557.001"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-LDAP-SIGN", Name: "LDAP signing disabled", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1557", Severity: "high",
		Summary:   "LDAP signing not required.",
		Detail:    "LDAP signing not required. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# LDAP signing disabled", "# MITRE T1557"},
		Markers:   []string{"LDAPServerIntegrity\\s*=\\s*1|ldap.?signing"},
		Detection: []string{"Hunt markers of LDAP signing disabled", "Map to T1557", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1557"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-EPA", Name: "EPA / channel binding", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1557", Severity: "medium",
		Summary:   "Missing EPA enables relay to HTTP.",
		Detail:    "Missing EPA enables relay to HTTP. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# EPA / channel binding", "# MITRE T1557"},
		Markers:   []string{"ExtendedProtection|channel.?binding"},
		Detection: []string{"Hunt markers of EPA / channel binding", "Map to T1557", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1557"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-WEBDAV", Name: "WebDAV lateral auth", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021", Severity: "medium",
		Summary:   "WebClient service auth coerce path.",
		Detail:    "WebClient service auth coerce path. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WebDAV lateral auth", "# MITRE T1021"},
		Markers:   []string{"WebClient|WebDAV.*auth"},
		Detection: []string{"Hunt markers of WebDAV lateral auth", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
	{
		ID: "LAT-RPC", Name: "RPC-based lateral", Category: "Lateral", Platform: "windows",
		Tactic: "TA0008", Technique: "T1021", Severity: "medium",
		Summary:   "Remote RPC activation paths.",
		Detail:    "Remote RPC activation paths. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# RPC-based lateral", "# MITRE T1021"},
		Markers:   []string{"RpcBinding|ncacn_np|ncacn_ip_tcp"},
		Detection: []string{"Hunt markers of RPC-based lateral", "Map to T1021", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1021"},
		Tags:      []string{"lateral", "movement"},
	},
}

// catalogByID returns the entry with the given id, or ok=false.
func catalogByID(id string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// categories returns the sorted distinct category set in the catalog.
func categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Category != "" && !seen[e.Category] {
			seen[e.Category] = true
			out = append(out, e.Category)
		}
	}
	sort.Strings(out)
	return out
}

// platforms returns the sorted distinct platform set in the catalog.
func platforms() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Platform != "" && !seen[e.Platform] {
			seen[e.Platform] = true
			out = append(out, e.Platform)
		}
	}
	sort.Strings(out)
	return out
}

// tactics returns the sorted distinct MITRE tactic set.
func tactics() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Tactic != "" && !seen[e.Tactic] {
			seen[e.Tactic] = true
			out = append(out, e.Tactic)
		}
	}
	sort.Strings(out)
	return out
}

// searchCatalog matches a free-text query against most text fields.
func searchCatalog(q string) []CatalogEntry {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	var out []CatalogEntry
	for _, e := range catalog {
		hay := strings.ToLower(strings.Join([]string{e.ID, e.Name, e.Category, e.Platform, e.Tactic, e.Technique, e.Summary, e.Detail, strings.Join(e.Commands, " "), strings.Join(e.Tags, " ")}, " "))
		all := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				all = false
				break
			}
		}
		if all {
			out = append(out, e)
		}
	}
	return out
}

// filterByCategory returns catalog entries in a category (case-insensitive).
func filterByCategory(cat string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Category, cat) {
			out = append(out, e)
		}
	}
	return out
}

// filterByPlatform returns catalog entries for a platform.
func filterByPlatform(p string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Platform, p) || strings.EqualFold(e.Platform, "any") || strings.EqualFold(e.Platform, "cross") {
			out = append(out, e)
		}
	}
	return out
}

// severityCounts tallies findings by severity.
func severityCounts(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[strings.ToLower(f.Severity)]++
	}
	return m
}

// ====================================================================
//  GRADING ENGINE
// ====================================================================

// gradeFor converts an accumulated risk score into an A+..F grade.
func gradeFor(score int) string {
	switch {
	case score <= 0:
		return "A+"
	case score < 10:
		return "A"
	case score < 25:
		return "B"
	case score < 50:
		return "C"
	case score < 90:
		return "D"
	case score < 150:
		return "E"
	default:
		return "F"
	}
}

// scoreFindings sums weighted severities into a single risk score.
func scoreFindings(fs []Finding) int {
	total := 0
	for _, f := range fs {
		w := sevWeight[strings.ToLower(f.Severity)]
		if w == 0 {
			w = 3
		}
		total += w
	}
	return total
}

// gradeExplain returns a short human explanation of a grade.
func gradeExplain(g string) string {
	switch g {
	case "A+":
		return "No material exposure observed in this analysis."
	case "A":
		return "Minimal exposure; only low-impact items present."
	case "B":
		return "Minor exposure; review flagged items at leisure."
	case "C":
		return "Moderate exposure; remediation recommended."
	case "D":
		return "Significant exposure; prioritise remediation."
	case "E":
		return "Severe exposure; urgent remediation required."
	default:
		return "Critical exposure; treat as actively exploitable."
	}
}

// ====================================================================
//  MARKER SCANNER
// ====================================================================

// compiledMarker pairs a catalog entry with a compiled regex marker.
type compiledMarker struct {
	entry CatalogEntry
	re    *regexp.Regexp
	raw   string
}

// buildMarkers compiles every marker in the catalog once. Markers that
// fail to compile as regex are matched as literal substrings instead.
func buildMarkers() []compiledMarker {
	var out []compiledMarker
	for _, e := range catalog {
		for _, m := range e.Markers {
			re, err := regexp.Compile("(?i)" + m)
			if err != nil {
				re = nil
			}
			out = append(out, compiledMarker{entry: e, re: re, raw: m})
		}
	}
	return out
}

// scanReader reads a stream line by line and matches catalog markers,
// producing one finding per (entry, line) hit. Deduplicated per entry/line.
func scanReader(name string, r io.Reader) []Finding {
	markers := buildMarkers()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	var findings []Finding
	seen := map[string]bool{}
	lineNo := 0
	for sc.Scan() {
		lineNo++
		text := sc.Text()
		low := strings.ToLower(text)
		for _, cm := range markers {
			hit := false
			if cm.re != nil {
				hit = cm.re.MatchString(text)
			} else {
				hit = strings.Contains(low, strings.ToLower(cm.raw))
			}
			if !hit {
				continue
			}
			key := cm.entry.ID + "#" + strconv.Itoa(lineNo)
			if seen[key] {
				continue
			}
			seen[key] = true
			ev := strings.TrimSpace(text)
			if len(ev) > 200 {
				ev = ev[:200] + "…"
			}
			findings = append(findings, Finding{
				RuleID:    cm.entry.ID,
				Title:     cm.entry.Name,
				Severity:  cm.entry.Severity,
				Score:     sevWeight[strings.ToLower(cm.entry.Severity)],
				Tactic:    cm.entry.Tactic,
				Technique: cm.entry.Technique,
				File:      name,
				Line:      lineNo,
				Evidence:  ev,
				Detail:    cm.entry.Summary,
				Detection: strings.Join(cm.entry.Detection, "; "),
				Refs:      cm.entry.Refs,
				Fprint:    fingerprint(cm.entry.ID, name, strconv.Itoa(lineNo)),
			})
		}
	}
	sortFindings(findings)
	return findings
}

// scanFile opens a file and scans it.
func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanReader(filepath.Base(path), f), nil
}

// sortFindings orders findings by severity (desc) then file/line.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := sevRank[strings.ToLower(fs[i].Severity)], sevRank[strings.ToLower(fs[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// ====================================================================
//  SHANNON ENTROPY (used by several analyzers)
// ====================================================================

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyGrade labels an entropy value.
func entropyGrade(h float64) string {
	switch {
	case h >= 7.5:
		return "very-high (packed/encrypted)"
	case h >= 6.5:
		return "high (compressed/encoded)"
	case h >= 5.0:
		return "moderate"
	case h >= 3.0:
		return "low"
	default:
		return "very-low (plain/structured)"
	}
}

// ====================================================================
//  COMMON DECODERS (deobfuscation helpers reused by tools)
// ====================================================================

// tryBase64 decodes a base64 token if it looks like one.
func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 8 || len(s)%4 != 0 {
		// try standard anyway with padding tolerance
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := dec.DecodeString(s); err == nil && len(b) > 0 && isMostlyPrintable(b) {
			return string(b), true
		}
	}
	return "", false
}

// tryBase64UTF16 decodes PowerShell -EncodedCommand (UTF-16LE base64).
func tryBase64UTF16(s string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) < 2 {
		return "", false
	}
	// strip UTF-16LE: take every other byte
	var out []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 {
			out = append(out, b[i])
		}
	}
	if len(out) > 0 && isMostlyPrintable(out) {
		return string(out), true
	}
	return "", false
}

// isMostlyPrintable reports whether a buffer is mostly printable ASCII.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

// hexDecodeStr decodes a hex string if valid.
func hexDecodeStr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 0 || len(s)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil || !isMostlyPrintable(b) {
		return "", false
	}
	return string(b), true
}

// rot13 applies the classic ROT13 substitution.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// xorBytes XORs a buffer with a repeating key (lab decode helper).
func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

// ====================================================================
//  REPORT BUILD + GRADING
// ====================================================================

func buildReport(mode, target string, fs []Finding) Report {
	sortFindings(fs)
	score := scoreFindings(fs)
	g := gradeFor(score)
	sc := severityCounts(fs)
	summary := fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low, %d info.",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"])
	return Report{
		Tool:       APPNAME,
		Version:    VERSION,
		Tagline:    TAGLINE,
		Generated:  time.Now().Format(time.RFC3339),
		Target:     target,
		Mode:       mode,
		Findings:   fs,
		Grade:      g,
		Score:      score,
		Summary:    summary,
		MitrePrime: PRIMARY_MITRE,
	}
}

// ====================================================================
//  EXPORT ENGINE  (txt / md / json / csv / sarif)
// ====================================================================

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("OWL " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("Version " + r.Version + "   Generated " + r.Generated + "\n")
	b.WriteString("Author khaled.s.haddad   owlsec.org\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	if r.Target != "" {
		b.WriteString("Target : " + r.Target + "\n")
	}
	b.WriteString("Mode   : " + r.Mode + "\n")
	b.WriteString("Primary MITRE : " + r.MitrePrime + "\n")
	b.WriteString("Grade  : " + r.Grade + " (score " + strconv.Itoa(r.Score) + ") — " + gradeExplain(r.Grade) + "\n")
	b.WriteString("Summary: " + r.Summary + "\n")
	b.WriteString(strings.Repeat("-", 72) + "\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s  (%s)\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("    Rule      : " + f.RuleID + "\n")
		b.WriteString("    MITRE     : " + f.Technique + "  " + f.Tactic + "\n")
		if f.File != "" {
			b.WriteString(fmt.Sprintf("    Location  : %s:%d\n", f.File, f.Line))
		}
		if f.Evidence != "" {
			b.WriteString("    Evidence  : " + f.Evidence + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    Detail    : " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("    Detection : " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("    Refs      : " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("    Fingerprint: " + f.Fprint + "\n\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# OWL " + r.Tool + "\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	if r.Target != "" {
		b.WriteString("| Target | " + r.Target + " |\n")
	}
	b.WriteString("| Mode | " + r.Mode + " |\n")
	b.WriteString("| Primary MITRE | " + r.MitrePrime + " |\n")
	b.WriteString("| Grade | **" + r.Grade + "** (score " + strconv.Itoa(r.Score) + ") |\n")
	b.WriteString("| Summary | " + r.Summary + " |\n\n")
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}
	b.WriteString("| # | Severity | Title | MITRE | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for i, f := range r.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ev := strings.ReplaceAll(f.Evidence, "|", "\\|")
		if len(ev) > 60 {
			ev = ev[:60] + "…"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n", i+1, strings.ToUpper(f.Severity), f.Title, f.Technique, loc, ev))
	}
	b.WriteString("\n### Detail\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("#### %d. %s (%s)\n\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("- Rule: `" + f.RuleID + "`\n")
		b.WriteString("- MITRE: " + f.Technique + " / " + f.Tactic + "\n")
		if f.Detail != "" {
			b.WriteString("- Detail: " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("- Detection: " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("- Refs: " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "ruleId", "title", "tactic", "technique", "file", "line", "evidence", "detection", "fingerprint"})
	for i, f := range r.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1), f.Severity, strconv.Itoa(f.Score), f.RuleID, f.Title,
			f.Tactic, f.Technique, f.File, strconv.Itoa(f.Line), f.Evidence, f.Detection, f.Fprint,
		})
	}
	w.Flush()
	return buf.String()
}

// SARIF 2.1.0 structures (minimal, valid)
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifText         `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fprints   map[string]string `json:"fingerprints,omitempty"`
	Props     map[string]string `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func exportSARIF(r Report) string {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Detail},
				HelpURI:          "https://owlsec.org/" + strings.ToLower(APPNAME),
				Properties:       map[string]string{"tactic": f.Tactic, "technique": f.Technique, "severity": f.Severity},
			}
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + ": " + f.Detail},
			Fprints: map[string]string{"owl/v1": f.Fprint},
			Props:   map[string]string{"severity": f.Severity, "technique": f.Technique},
		}
		if f.File != "" {
			reg := &sarifRegion{StartLine: f.Line}
			if f.Line <= 0 {
				reg = nil
			}
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: reg}}}
		}
		results = append(results, res)
	}
	var rules []sarifRule
	for _, v := range ruleSet {
		rules = append(rules, v)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "OWL-" + APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	buf, _ := json.MarshalIndent(log, "", "  ")
	return string(buf)
}

// renderReport selects a format.
func renderReport(r Report, format string) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

// writeOut writes rendered output to a file or stdout.
// ====================================================================
//  v1.1 — DOT export, scan diff, baseline suppression, severity gate
// ====================================================================

// lateralMapDOT renders the reachability edges as a Graphviz digraph.
func lateralMapDOT(edges []latEdge) string {
	var b strings.Builder
	b.WriteString("digraph lateral {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=rounded, fontname=\"monospace\"];\n")
	sevColor := map[string]string{"critical": "red", "high": "orange", "medium": "gold", "low": "gray", "info": "lightgray"}
	for _, e := range edges {
		c := sevColor[strings.ToLower(e.Severity)]
		if c == "" {
			c = "black"
		}
		label := e.Technique
		if e.Requires != "" {
			label += "\\nreq: " + e.Requires
		}
		b.WriteString(fmt.Sprintf("  %q -> %q [label=%q, color=%s];\n", e.From, e.To, label, c))
	}
	b.WriteString("}\n")
	return b.String()
}

// loadReport reads a previously exported JSON report.
func loadReport(path string) (Report, error) {
	var r Report
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	return r, err
}

// diffFindings compares two finding sets by fingerprint.
func diffFindings(oldF, newF []Finding) (added, resolved []Finding) {
	oldSet := map[string]bool{}
	for _, f := range oldF {
		oldSet[f.Fprint] = true
	}
	newSet := map[string]bool{}
	for _, f := range newF {
		newSet[f.Fprint] = true
		if !oldSet[f.Fprint] {
			added = append(added, f)
		}
	}
	for _, f := range oldF {
		if !newSet[f.Fprint] {
			resolved = append(resolved, f)
		}
	}
	return
}

// loadBaseline reads fingerprints to suppress: a JSON report, or a plain text
// file of one fingerprint per line (# comments allowed).
func loadBaseline(path string) (map[string]bool, error) {
	set := map[string]bool{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if r, err := func() (Report, error) { var r Report; e := json.Unmarshal(raw, &r); return r, e }(); err == nil && len(r.Findings) > 0 {
		for _, f := range r.Findings {
			set[f.Fprint] = true
		}
		return set, nil
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		set[s] = true
	}
	return set, nil
}

// applyBaseline drops findings whose fingerprint is in the suppression set.
func applyBaseline(fs []Finding, base map[string]bool) []Finding {
	if len(base) == 0 {
		return fs
	}
	var out []Finding
	for _, f := range fs {
		if !base[f.Fprint] {
			out = append(out, f)
		}
	}
	return out
}

// maxSeverity returns the highest severity rank present in findings.
func maxSeverity(fs []Finding) int {
	m := 0
	for _, f := range fs {
		if r := sevRank[strings.ToLower(f.Severity)]; r > m {
			m = r
		}
	}
	return m
}

func writeOut(content, path string) error {
	if path == "" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ====================================================================
//  HOW TO USE SCREEN  (mandatory — menu item + --howto flag)
// ====================================================================

type HowtoSection struct {
	Title string
	Lines []string
}

var howtoSections = []HowtoSection{
	{Title: "LEGAL & ETHICAL WARNING", Lines: []string{
		"OLateral is for AUTHORIZED security testing, detection engineering and education ONLY.",
		"Use it exclusively on systems, files and logs you own or are explicitly permitted",
		"in writing to assess. Unauthorized use of the techniques catalogued here may be a crime.",
		"This tool is an OFFLINE analyzer / planner / catalog: it does NOT launch live attacks",
		"against third-party systems. You are solely responsible for staying in scope.",
	}},
	{Title: "HOW TO USE", Lines: []string{
		"1. Browse the catalog for techniques, markers, detection and MITRE mapping.",
		"2. Collect authorized offline inputs (configs, logs, captures, dumps).",
		"3. Run: OLateral --scan input.txt --format sarif --output out.sarif",
		"4. Use 'Map lateral movement' for the tool-specific analyzer.",
		"5. Use 'MITRE technique index' to pivot by technique.",
		"6. Export findings as txt|md|json|csv|sarif; generate Sigma via --sigma.",
	}},
	{Title: "MENU OPTIONS", Lines: []string{
		"[1]  Catalog browser   — list/search/filter and view full entry cards.",
		"[2]  Scan input file   — regex marker scan into graded findings.",
		"[3]  Run planner       — tool-specific planner / graph / builder.",
		"[4]  Catalog statistics — severity/category/platform breakdown.",
		"[5]  Export            — dump catalog/last report in any of 5 formats.",
		"[6]  Run demo          — synthetic self-contained demonstration.",
		"[7]  ATT&CK coverage matrix — tactic/technique coverage view.",
		"[8]  Detection rules (Sigma) — generate Sigma-style rules.",
		"[9]  Map lateral movement — the tool-specific reachability analyzer.",
		"[10] MITRE technique index — pivot by technique ID.",
		"[H]  Help & Usage      — this screen.",
		"[0]  Exit.  CLI mirrors: --howto, --demo, --scan, --search, --plan, --sigma.",
	}},
	{Title: "REQUIREMENTS", Lines: []string{
		"- Offline analyzer/planner; Go stdlib only; no live attacks.",
		"- Authorized testing only; written permission required.",
		"- Inputs are text configs, logs, or synthetic lab samples.",
	}},
	{Title: "FEATURE / PROTOCOL NOTES", Lines: []string{
		"Builds a demo lateral reachability map with technique+requirement edges.",
		"Catalog covers SMB/WMI/WinRM/RDP/SSH/DCOM/PtH/PtT/relay/ADCS/cloud.",
		"Planning/analysis only — does not perform live lateral movement.",
	}},
	{Title: "v1.1 CLI WORKFLOW", Lines: []string{
		"--dot            export the reachability map as Graphviz (pipe to `dot -Tpng`).",
		"--baseline FILE  suppress known findings (a prior JSON report or a list of",
		"                 fingerprints, one per line) so only new issues surface.",
		"--diff OLD.json  compare this scan with a previous report; prints +new / -resolved",
		"                 and exits 1 when new findings appear.",
		"--fail-on SEV    CI gate: exit 3 if any finding is at/above SEV (critical|high|…).",
	}},
}

// showHowto renders the HOW TO USE screen.
func showHowto() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  HOW TO USE — "+APPNAME, CY+B))
	line(64)
	for _, s := range howtoSections {
		fmt.Println()
		fmt.Println("  " + col("▸ "+s.Title, CY+B))
		for _, ln := range s.Lines {
			if ln == "" {
				fmt.Println()
				continue
			}
			fmt.Println("    " + col(ln, W))
		}
	}
	line(64)
	fmt.Println("  " + col("Primary MITRE mapping: ", DIM) + col(PRIMARY_MITRE, CY))
	fmt.Println("  " + col("Authorized testing only — see LEGAL & ETHICAL WARNING above.", GY))
}

// howtoText returns the HOW TO USE content as plain text (for --howto).
func howtoText() string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — HOW TO USE\n")
	b.WriteString(TAGLINE + "\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	for _, s := range howtoSections {
		b.WriteString("\n## " + s.Title + "\n")
		for _, ln := range s.Lines {
			b.WriteString("  " + ln + "\n")
		}
	}
	b.WriteString("\nPrimary MITRE mapping: " + PRIMARY_MITRE + "\n")
	return b.String()
}

// ====================================================================
//  CATALOG BROWSER (shared interactive + CLI views)
// ====================================================================

// printCatalogTable prints a compact table of entries.
func printCatalogTable(entries []CatalogEntry) {
	if len(entries) == 0 {
		warnMsg("No catalog entries match.")
		return
	}
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.ID, trunc(e.Name, 34), e.Platform, strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"ID", "NAME", "PLATFORM", "SEV", "MITRE"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d entr%s.", len(entries), plural(len(entries))))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// showEntry prints a full catalog entry card.
func showEntry(e CatalogEntry) {
	fmt.Println()
	fmt.Println("  " + col("╭─ "+e.ID+" — "+e.Name, CY+B))
	fmt.Println("  " + col("│ Category : ", DR) + col(e.Category, W))
	fmt.Println("  " + col("│ Platform : ", DR) + col(e.Platform, W))
	fmt.Println("  " + col("│ Severity : ", DR) + col(strings.ToUpper(e.Severity), sevColor(e.Severity)))
	fmt.Println("  " + col("│ Tactic   : ", DR) + col(e.Tactic, W))
	fmt.Println("  " + col("│ Technique: ", DR) + col(e.Technique, W))
	fmt.Println("  " + col("╰─", DR))
	fmt.Println("  " + col("Summary: ", CY+B) + col(e.Summary, W))
	if e.Detail != "" {
		fmt.Println()
		for _, ln := range wrap(e.Detail, 78) {
			fmt.Println("    " + col(ln, GY))
		}
	}
	if len(e.Commands) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Example / reference commands:", CY+B))
		for _, c := range e.Commands {
			fmt.Println("    " + col("$ ", DR) + col(c, W))
		}
	}
	if len(e.Markers) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Scan markers (regex):", CY+B))
		for _, m := range e.Markers {
			fmt.Println("    " + col(m, YLW))
		}
	}
	if len(e.Detection) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Detection guidance:", CY+B))
		for _, d := range e.Detection {
			fmt.Println("    " + col("• "+d, W))
		}
	}
	if len(e.Refs) > 0 {
		fmt.Println()
		fmt.Println("  " + col("References: ", DIM) + col(strings.Join(e.Refs, "  "), GY))
	}
}

// wrap wraps text to a width.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ====================================================================
//  GENERIC PLANNER (catalog -> prioritized action plan)
// ====================================================================

// genericPlan ranks catalog entries into a prioritized, MITRE-tagged plan.
func genericPlan() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  PRIORITIZED PLAN (catalog-ranked)", CY+B))
	line(64)
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	rows := [][]string{}
	for i, e := range entries {
		if i >= 25 {
			break
		}
		rows = append(rows, []string{strconv.Itoa(i + 1), e.ID, trunc(e.Name, 30), strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"#", "ID", "STEP", "SEV", "MITRE"}, rows)
}

// genericDemo runs a synthetic self-contained scan over an embedded sample.
func genericDemo() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DEMO — synthetic self-contained run", CY+B))
	line(64)
	sample := demoSample()
	fs := scanReader("demo-sample.txt", strings.NewReader(sample))
	rep := buildReport("demo", "demo-sample.txt", fs)
	printFindings(rep)
}

// printFindings prints a report's findings + grade to the TUI.
func printFindings(rep Report) {
	if len(rep.Findings) == 0 {
		okMsg("No findings in this run.")
	} else {
		rows := [][]string{}
		for i, f := range rep.Findings {
			rows = append(rows, []string{strconv.Itoa(i + 1), strings.ToUpper(f.Severity), trunc(f.Title, 32), f.Technique, fmt.Sprintf("%s:%d", f.File, f.Line)})
		}
		table([]string{"#", "SEV", "FINDING", "MITRE", "LOC"}, rows)
	}
	fmt.Println()
	gradeLineOut(rep)
}

func gradeLineOut(rep Report) {
	fmt.Println("  " + col("Grade : ", CY+B) + col(rep.Grade, sevColorForGrade(rep.Grade)+B) + col("  score "+strconv.Itoa(rep.Score), GY))
	fmt.Println("  " + col(gradeExplain(rep.Grade), GY))
	fmt.Println("  " + col(rep.Summary, W))
}

func sevColorForGrade(g string) string {
	switch g {
	case "A+", "A":
		return GRN
	case "B", "C":
		return YLW
	default:
		return R
	}
}

// ====================================================================
//  IOC EXTRACTOR + TIMELINE + FINDING MERGE UTILITIES
// ====================================================================

// extractIOCs pulls IPv4, URLs, emails, and Windows paths from text.
func extractIOCs(text string) (ips, urls, emails, paths []string) {
	ipRe := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	urlRe := regexp.MustCompile(`https?://[^\s"'<>]{4,}`)
	emRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	pathRe := regexp.MustCompile(`(?i)(?:[A-Za-z]:\\|\\\\|/var/|/tmp/|/etc/|/home/|/usr/)[^\s"'<>]{2,}`)
	seen := map[string]bool{}
	add := func(list *[]string, v string) {
		if seen[v] {
			return
		}
		seen[v] = true
		*list = append(*list, v)
	}
	for _, m := range ipRe.FindAllString(text, 50) {
		add(&ips, m)
	}
	for _, m := range urlRe.FindAllString(text, 50) {
		add(&urls, trunc(m, 160))
	}
	for _, m := range emRe.FindAllString(text, 50) {
		add(&emails, m)
	}
	for _, m := range pathRe.FindAllString(text, 50) {
		add(&paths, trunc(m, 120))
	}
	return
}

// iocsToFindings converts extracted IOCs into Finding records.
func iocsToFindings(src string, ips, urls, emails, paths []string) []Finding {
	var fs []Finding
	for _, v := range ips {
		fs = append(fs, Finding{RuleID: "IOC-IP", Title: "IPv4 address", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1016", File: src, Evidence: v,
			Detail: "Extracted IPv4 indicator.", Fprint: fingerprint("ip", v)})
	}
	for _, v := range urls {
		fs = append(fs, Finding{RuleID: "IOC-URL", Title: "URL", Severity: "info",
			Score: 1, Tactic: "Command and Control", Technique: "T1071", File: src, Evidence: v,
			Detail: "Extracted URL indicator.", Fprint: fingerprint("url", v)})
	}
	for _, v := range emails {
		fs = append(fs, Finding{RuleID: "IOC-EMAIL", Title: "Email address", Severity: "info",
			Score: 1, Tactic: "Initial Access", Technique: "T1566", File: src, Evidence: v,
			Detail: "Extracted email indicator.", Fprint: fingerprint("em", v)})
	}
	for _, v := range paths {
		fs = append(fs, Finding{RuleID: "IOC-PATH", Title: "Filesystem path", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1083", File: src, Evidence: v,
			Detail: "Extracted path indicator.", Fprint: fingerprint("path", v)})
	}
	return fs
}

// mergeFindings concatenates and de-duplicates findings by fingerprint.
func mergeFindings(sets ...[]Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, set := range sets {
		for _, f := range set {
			key := f.Fprint
			if key == "" {
				key = fingerprint(f.RuleID, f.Title, f.Evidence, strconv.Itoa(f.Line))
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// timelineEvent is a simple ordered event for planner/report timelines.
type timelineEvent struct {
	TS     string
	Phase  string
	Title  string
	Detail string
}

// buildTimeline renders a phase-ordered timeline from findings' tactics.
func buildTimeline(fs []Finding) []timelineEvent {
	phaseOf := map[string]string{
		"Initial Access": "1-Initial", "Execution": "2-Execution",
		"Persistence": "3-Persist", "Privilege Escalation": "4-PrivEsc",
		"Defense Evasion": "5-Evasion", "Credential Access": "6-Creds",
		"Discovery": "7-Discover", "Lateral Movement": "8-Lateral",
		"Collection": "9-Collect", "Command and Control": "A-C2",
		"Exfiltration": "B-Exfil", "Impact": "C-Impact",
	}
	var evs []timelineEvent
	for i, f := range fs {
		phase := phaseOf[f.Tactic]
		if phase == "" {
			phase = "Z-Other"
		}
		evs = append(evs, timelineEvent{
			TS: fmt.Sprintf("T+%03d", i+1), Phase: phase,
			Title: f.Title, Detail: trunc(f.Detail, 80),
		})
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Phase < evs[j].Phase })
	return evs
}

// printTimeline displays a timeline table in the TUI.
func printTimeline(evs []timelineEvent) {
	if len(evs) == 0 {
		warnMsg("No timeline events.")
		return
	}
	rows := [][]string{}
	for _, e := range evs {
		rows = append(rows, []string{e.TS, e.Phase, trunc(e.Title, 36), trunc(e.Detail, 40)})
	}
	table([]string{"TS", "PHASE", "EVENT", "DETAIL"}, rows)
}

// findingSummaryLine returns a one-line summary of a findings slice.
func findingSummaryLine(fs []Finding) string {
	sc := severityCounts(fs)
	return fmt.Sprintf("%d findings (crit=%d high=%d med=%d low=%d info=%d) grade=%s",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"],
		gradeFor(scoreFindings(fs)))
}

// writeFindingsBundle exports a report in all 5 formats under a directory prefix.
func writeFindingsBundle(rep Report, prefix string) error {
	formats := []string{"txt", "md", "json", "csv", "sarif"}
	for _, f := range formats {
		path := prefix + "." + f
		if f == "sarif" {
			path = prefix + ".sarif.json"
		}
		if err := os.WriteFile(path, []byte(renderReport(rep, f)), 0644); err != nil {
			return err
		}
		okMsg("Wrote " + path)
	}
	return nil
}

// countMarkers returns total compiled markers across the catalog.
func countMarkers() int {
	n := 0
	for _, e := range catalog {
		n += len(e.Markers)
	}
	return n
}

// topSeverity returns the highest severity present in a findings slice.
func topSeverity(fs []Finding) string {
	top := "info"
	for _, f := range fs {
		if sevRank[strings.ToLower(f.Severity)] > sevRank[top] {
			top = strings.ToLower(f.Severity)
		}
	}
	return top
}

// filterFindingsBySev returns findings at or above a minimum severity.
func filterFindingsBySev(fs []Finding, min string) []Finding {
	minR := sevRank[strings.ToLower(min)]
	var out []Finding
	for _, f := range fs {
		if sevRank[strings.ToLower(f.Severity)] >= minR {
			out = append(out, f)
		}
	}
	return out
}

// groupFindingsByTechnique groups findings by MITRE technique ID.
func groupFindingsByTechnique(fs []Finding) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range fs {
		k := f.Technique
		if k == "" {
			k = "(none)"
		}
		m[k] = append(m[k], f)
	}
	return m
}

// ====================================================================
//  ATT&CK COVERAGE MATRIX
// ====================================================================

// attackCoverage prints a tactic x technique coverage matrix derived from
// the catalog, useful for detection-engineering gap analysis.
func attackCoverage() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  ATT&CK COVERAGE MATRIX", CY+B))
	line(64)
	byTactic := map[string][]string{}
	techSeverity := map[string]string{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac] = append(byTactic[tac], e.Technique)
		if sevRank[strings.ToLower(e.Severity)] > sevRank[strings.ToLower(techSeverity[e.Technique])] {
			techSeverity[e.Technique] = e.Severity
		}
	}
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	rows := [][]string{}
	for _, tac := range tacs {
		uniq := uniqueSorted(byTactic[tac])
		rows = append(rows, []string{trunc(tac, 34), strconv.Itoa(len(byTactic[tac])), strconv.Itoa(len(uniq)), trunc(strings.Join(uniq, ","), 40)})
	}
	table([]string{"TACTIC", "ENTRIES", "TECHNIQUES", "IDS"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d distinct techniques across %d tactics.", len(techSeverity), len(tacs)))
}

// uniqueSorted returns a deduplicated, sorted copy of a string slice.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// attackCoverageText returns the coverage matrix as plain text (CLI).
func attackCoverageText() string {
	byTactic := map[string]int{}
	byTech := map[string]bool{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac]++
		byTech[e.Technique] = true
	}
	var b strings.Builder
	b.WriteString(APPNAME + " ATT&CK coverage: " + strconv.Itoa(len(byTech)) + " techniques\n")
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	for _, tac := range tacs {
		b.WriteString(fmt.Sprintf("  %-40s %d\n", tac, byTactic[tac]))
	}
	return b.String()
}

// ====================================================================
//  SIGMA-STYLE DETECTION RULE GENERATOR
// ====================================================================

// yamlEscape quotes a string for a simple inline YAML scalar.
func yamlEscape(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@") || strings.Contains(s, "\\") || strings.Contains(s, "\"") || strings.Contains(s, "'") {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return s
}

// generateSigma turns catalog entries into Sigma-like detection rules.
// The output is a best-effort Sigma skeleton for blue-team use; markers
// become CommandLine regex conditions. It is a generator, not a validator.
func generateSigma() string {
	var b strings.Builder
	for _, e := range catalog {
		if len(e.Markers) == 0 {
			continue
		}
		b.WriteString("title: " + yamlEscape(APPNAME+" - "+e.Name) + "\n")
		b.WriteString("id: " + fingerprint("sigma", APPNAME, e.ID) + "\n")
		b.WriteString("status: experimental\n")
		b.WriteString("description: " + yamlEscape(e.Summary) + "\n")
		b.WriteString("references:\n")
		for _, r := range e.Refs {
			b.WriteString("  - " + yamlEscape(r) + "\n")
		}
		b.WriteString("author: khaled.s.haddad (owlsec.org)\n")
		b.WriteString("tags:\n")
		b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(firstToken(e.Tactic), " ", "_")) + "\n")
		if e.Technique != "" {
			b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(e.Technique, ".", "_")) + "\n")
		}
		b.WriteString("logsource:\n")
		b.WriteString("  category: process_creation\n")
		b.WriteString("  product: " + yamlEscape(e.Platform) + "\n")
		b.WriteString("detection:\n")
		b.WriteString("  selection:\n")
		b.WriteString("    CommandLine|re:\n")
		for _, m := range e.Markers {
			b.WriteString("      - " + yamlEscape(m) + "\n")
		}
		b.WriteString("  condition: selection\n")
		b.WriteString("level: " + sigmaLevel(e.Severity) + "\n")
		b.WriteString("---\n")
	}
	return b.String()
}

// firstToken returns the first whitespace/slash-delimited token.
func firstToken(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == ' ' || r == '/' {
			return s[:i]
		}
	}
	if s == "" {
		return "execution"
	}
	return s
}

func sigmaLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "informational"
	}
}

// menuSigma shows generated Sigma rules and offers to export them.
func menuSigma() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  DETECTION RULES (SIGMA-STYLE)", CY+B))
	line(64)
	rules := generateSigma()
	count := strings.Count(rules, "---\n")
	info(fmt.Sprintf("Generated %d Sigma-style rule(s) from the catalog markers.", count))
	preview := rules
	if len(preview) > 1400 {
		preview = preview[:1400] + "\n... (truncated preview) ..."
	}
	fmt.Println(col(preview, GY))
	fmt.Println()
	if out := prompt("export to file? (path or blank)"); out != "" {
		if err := os.WriteFile(out, []byte(rules), 0644); err != nil {
			errMsg(err.Error())
		} else {
			okMsg("Wrote Sigma rules to " + out)
		}
	}
	pause()
}

// ====================================================================
//  TOOL-SPECIFIC EXTRA ENGINE
// ====================================================================

// parseKeyValueLines parses "key=value" / "key: value" style config lines.
func parseKeyValueLines(text string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "//") || strings.HasPrefix(ln, ";") {
			continue
		}
		sep := "="
		if i := strings.Index(ln, ":"); i > 0 && (strings.Index(ln, "=") < 0 || i < strings.Index(ln, "=")) {
			sep = ":"
		}
		parts := strings.SplitN(ln, sep, 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

// scoreConfigMap grades a set of config key=value pairs against expected hardening.
type configRule struct {
	Key      string
	BadVals  []string
	GoodVals []string
	Sev      string
	Title    string
	Tech     string
	Detail   string
}

func auditConfigMap(src string, cfg map[string]string, rules []configRule) []Finding {
	var fs []Finding
	for _, r := range rules {
		v, ok := cfg[r.Key]
		if !ok {
			continue
		}
		low := strings.ToLower(v)
		bad := false
		for _, b := range r.BadVals {
			if strings.Contains(low, strings.ToLower(b)) {
				bad = true
				break
			}
		}
		if !bad && len(r.GoodVals) > 0 {
			good := false
			for _, g := range r.GoodVals {
				if strings.EqualFold(v, g) {
					good = true
					break
				}
			}
			if !good {
				bad = true
			}
		}
		if !bad {
			continue
		}
		fs = append(fs, Finding{
			RuleID: "CFG-" + r.Key, Title: r.Title, Severity: r.Sev,
			Score: sevWeight[strings.ToLower(r.Sev)], Tactic: "Defense Evasion",
			Technique: r.Tech, File: src, Evidence: r.Key + "=" + v,
			Detail: r.Detail, Fprint: fingerprint(r.Key, v),
		})
	}
	return fs
}

type latEdge struct{ From, To, Technique, Requires, Severity string }

func demoLateralMap() []latEdge {
	return []latEdge{
		{"WS01", "FS01", "T1021.002 SMB/PsExec", "local admin hash", "high"},
		{"FS01", "SQL01", "T1047 WMI", "svc-sql token", "high"},
		{"SQL01", "DC01", "T1003.006 DCSync", "replicating rights", "critical"},
		{"WS01", "APP01", "T1021.006 WinRM", "WinRM enabled + cred", "medium"},
		{"APP01", "DC01", "T1550.003 PtT", "TGT from unconstrained", "critical"},
	}
}

func menuScanSpecial() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  LATERAL-MOVEMENT MAPPER", CY+B))
	line(64)
	edges := demoLateralMap()
	rows := [][]string{}
	var fs []Finding
	for i, e := range edges {
		rows = append(rows, []string{strconv.Itoa(i + 1), e.From, e.To, e.Technique, e.Severity})
		fs = append(fs, Finding{
			RuleID: fmt.Sprintf("LAT-EDGE-%d", i+1), Title: e.From + " → " + e.To + " via " + e.Technique,
			Severity: e.Severity, Score: sevWeight[e.Severity], Tactic: "Lateral Movement",
			Technique: strings.Fields(e.Technique)[0], Evidence: "requires: " + e.Requires,
			Detail: e.Technique, Fprint: fingerprint(e.From, e.To, e.Technique),
		})
	}
	table([]string{"#", "FROM", "TO", "TECHNIQUE", "SEV"}, rows)
	p := prompt("optional command log to scan (blank=map only)")
	if p != "" {
		if extra, err := scanFile(p); err == nil {
			fs = append(fs, extra...)
		}
	}
	rep := buildReport("lateral-map", "graph", fs)
	fmt.Println()
	printFindings(rep)
	if f := prompt("export format (blank=skip)"); f != "" {
		out := prompt("output file (blank=stdout)")
		writeOut(renderReport(rep, f), out)
		okMsg("Exported.")
	}
	pause()
}

func menuShowMitre() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  MITRE TECHNIQUE INDEX", CY+B))
	line(64)
	by := map[string][]CatalogEntry{}
	for _, e := range catalog {
		by[e.Technique] = append(by[e.Technique], e)
	}
	var keys []string
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(len(by[k])), trunc(by[k][0].Name, 40), by[k][0].Severity})
	}
	table([]string{"TECHNIQUE", "N", "EXAMPLE", "SEV"}, rows)
	pause()
}
func init() {
	planReportFn = func() Report {
		entries := append([]CatalogEntry{}, catalog...)
		sort.SliceStable(entries, func(i, j int) bool {
			return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
		})
		return buildReport("plan", "catalog", entriesToFindings(entries))
	}
}

// ====================================================================
//  DEMO SAMPLE + PLAN REPORT (hooks; tools may override planReportFn)
// ====================================================================

func demoSample() string {
	return "# synthetic OLateral sample (authorized lab)\npsexec \\\\FS01 cmd\nwmic /node:SQL01 process call create calc\nEnter-PSSession -ComputerName APP01\nsekurlsa::pth /user:admin /ntlm:aad3...\nRubeus ptt /ticket:ticket.kirbi\nsc \\\\HOST create evil binPath= cmd\nschtasks /S HOST /create /tn t /tr cmd\nntlmrelayx -t smb://DC01\nPetitPotam\nxp_cmdshell\nProxyJump\nRequireSecuritySignature = 0\n"
}

// planReportFn lets a tool supply a custom planner report for CLI --plan.
var planReportFn = defaultPlanReport

// planReport returns the planner report for the CLI --plan path.
func planReport() Report { return planReportFn() }

// defaultPlanReport ranks the catalog by severity into a plan report.
func defaultPlanReport() Report {
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	return buildReport("plan", "catalog", entriesToFindings(entries))
}

// ====================================================================
//  DEMO SAMPLE + runDemo/runPlan dispatch
// ====================================================================

func runDemo() {
	genericDemo()
}

func runPlan() {
	genericPlan()
}

// ====================================================================
//  INTERACTIVE TUI
// ====================================================================

func interactiveBrowse() {
	for {
		sel := menu("CATALOG BROWSER", []string{"List all", "Search", "By category", "By platform", "Show entry by ID", "Back"})
		switch sel {
		case "1":
			clear()
			banner()
			printCatalogTable(catalog)
			pause()
		case "2":
			q := prompt("query")
			clear()
			banner()
			printCatalogTable(searchCatalog(q))
			pause()
		case "3":
			cats := categories()
			fmt.Println()
			for i, c := range cats {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(c, W))
			}
			idx := prompt("category #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(cats) {
				clear()
				banner()
				printCatalogTable(filterByCategory(cats[n-1]))
				pause()
			}
		case "4":
			ps := platforms()
			fmt.Println()
			for i, p := range ps {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(p, W))
			}
			idx := prompt("platform #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(ps) {
				clear()
				banner()
				printCatalogTable(filterByPlatform(ps[n-1]))
				pause()
			}
		case "5":
			id := prompt("entry ID")
			if e, ok := catalogByID(id); ok {
				clear()
				banner()
				showEntry(e)
			} else {
				errMsg("No entry with ID " + id)
			}
			pause()
		case "6", "0", "00", "":
			return
		}
	}
}

func interactiveScan() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  SCAN INPUT FOR CATALOG MARKERS", CY+B))
	line(64)
	p := prompt("path to file")
	if p == "" {
		warnMsg("No path given.")
		pause()
		return
	}
	fs, err := scanFile(p)
	if err != nil {
		errMsg("Open failed: " + err.Error())
		pause()
		return
	}
	rep := buildReport("scan", p, fs)
	fmt.Println()
	printFindings(rep)
	fmt.Println()
	if yn := prompt("export? (format or blank)"); yn != "" {
		out := prompt("output file (blank=stdout)")
		writeOut(renderReport(rep, yn), out)
		okMsg("Exported.")
	}
	pause()
}

func interactiveStats() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  CATALOG STATISTICS", CY+B))
	line(64)
	bySev := map[string]int{}
	byCat := map[string]int{}
	byPlat := map[string]int{}
	markerCount := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		byPlat[e.Platform]++
		markerCount += len(e.Markers)
	}
	info(fmt.Sprintf("Catalog entries : %d", len(catalog)))
	info(fmt.Sprintf("Scan markers    : %d", markerCount))
	info(fmt.Sprintf("Categories      : %d", len(byCat)))
	info(fmt.Sprintf("Platforms       : %d", len(byPlat)))
	fmt.Println()
	fmt.Println("  " + col("By severity:", CY+B))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			bar := strings.Repeat("█", bySev[s])
			fmt.Printf("    %-9s %s %d\n", s, col(bar, sevColor(s)), bySev[s])
		}
	}
	fmt.Println()
	fmt.Println("  " + col("By category:", CY+B))
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("    %-28s %d\n", c, byCat[c])
	}
}

func interactiveExport() {
	clear()
	banner()
	fmt.Println("  " + col("⬡  EXPORT CATALOG / LAST REPORT", CY+B))
	line(64)
	rep := buildReport("catalog-dump", "catalog", catalogAsFindings())
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank=stdout)")
	if err := writeOut(renderReport(rep, f), out); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("Export complete.")
	}
	pause()
}

// catalogAsFindings turns the catalog into findings for a reference dump.
func catalogAsFindings() []Finding {
	var fs []Finding
	for _, e := range catalog {
		fs = append(fs, Finding{
			RuleID:    e.ID,
			Title:     e.Name,
			Severity:  e.Severity,
			Score:     sevWeight[strings.ToLower(e.Severity)],
			Tactic:    e.Tactic,
			Technique: e.Technique,
			Detail:    e.Summary,
			Detection: strings.Join(e.Detection, "; "),
			Refs:      e.Refs,
			Fprint:    fingerprint(e.ID),
		})
	}
	return fs
}

func mainMenu() {
	for {
		items := []string{"Catalog browser", "Scan input file", "Run planner", "Catalog statistics", "Export", "Run demo", "ATT&CK coverage matrix", "Detection rules (Sigma)"}
		items = append(items, []string{"Map lateral movement", "MITRE technique index"}...)
		sel := menu("MAIN MENU — "+APPNAME, items)
		switch strings.ToLower(sel) {
		case "1":
			interactiveBrowse()
		case "2":
			interactiveScan()
		case "3":
			runPlan()
			pause()
		case "4":
			interactiveStats()
			pause()
		case "5":
			interactiveExport()
		case "6":
			runDemo()
			pause()
		case "7":
			attackCoverage()
			pause()
		case "8":
			menuSigma()
		case "9":
			menuScanSpecial()
		case "10":
			menuShowMitre()
		case "h", "help", "?":
			showHowto()
			pause()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye. Stay authorized.")
			return
		}
	}
}

// ====================================================================
//  CLI
// ====================================================================

func usage() {
	banner()
	fmt.Println("  " + col("USAGE", CY+B) + col("  "+APPNAME+" [flags]", W))
	fmt.Println()
	fmt.Println("  Run with no flags for the interactive TUI.")
	fmt.Println()
	fmt.Println("  " + col("FLAGS", CY+B))
	flags := [][]string{
		{"-h, --help", "Show this help"},
		{"--version", "Print version and exit"},
		{"--howto", "Print the HOW TO USE screen (legal, steps, navigation)"},
		{"--demo", "Run a synthetic, self-contained demonstration"},
		{"--list", "List the full technique/binary catalog"},
		{"--search Q", "Search the catalog for Q"},
		{"--category C", "Filter catalog by category"},
		{"--platform P", "Filter catalog by platform"},
		{"--id ID", "Show a single catalog entry by ID"},
		{"--scan FILE", "Scan FILE for catalog markers -> findings"},
		{"--input FILE", "Alias for --scan"},
		{"--plan", "Run the tool's planner / graph / builder"},
		{"--sigma", "Generate Sigma-style detection rules from the catalog"},
		{"--coverage", "Print an ATT&CK tactic coverage matrix"},
		{"--stats", "Print catalog statistics"},
		{"--format F", "Output format: txt|md|json|csv|sarif (default txt)"},
		{"--output FILE", "Write output to FILE instead of stdout"},
		{"--dot", "Export the reachability map as a Graphviz .dot graph"},
		{"--baseline FILE", "Suppress findings whose fingerprint is in FILE (report or list)"},
		{"--diff OLD.json", "Diff this scan against a previous JSON report (exit 1 if new)"},
		{"--fail-on SEV", "Exit 3 if a scan finding is at/above SEV (critical|high|…)"},
		{"--no-color", "Disable ANSI colors"},
	}
	for _, f := range flags {
		fmt.Printf("    %s  %s\n", col(pad(f[0], 16), W), col(f[1], GY))
	}
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Println("    " + col(APPNAME+" --scan input.log --format sarif --output out.sarif", GY))
	fmt.Println("    " + col(APPNAME+" --scan input.log --fail-on high   # CI gate", GY))
	fmt.Println("    " + col(APPNAME+" --scan input.log --baseline known.json", GY))
	fmt.Println("    " + col(APPNAME+" --scan input.log --diff last-scan.json", GY))
	fmt.Println("    " + col(APPNAME+" --dot --output lateral.dot", GY))
	fmt.Println()
	fmt.Println("  " + col("Primary MITRE: ", DIM) + col(PRIMARY_MITRE, CY) + col("   Authorized testing only.", GY))
}

func main() {
	var (
		fHelp     = flag.Bool("help", false, "")
		fH        = flag.Bool("h", false, "")
		fVersion  = flag.Bool("version", false, "")
		fHowto    = flag.Bool("howto", false, "")
		fDemo     = flag.Bool("demo", false, "")
		fList     = flag.Bool("list", false, "")
		fStats    = flag.Bool("stats", false, "")
		fPlan     = flag.Bool("plan", false, "")
		fSigma    = flag.Bool("sigma", false, "")
		fCover    = flag.Bool("coverage", false, "")
		fSearch   = flag.String("search", "", "")
		fCat      = flag.String("category", "", "")
		fPlat     = flag.String("platform", "", "")
		fID       = flag.String("id", "", "")
		fScan     = flag.String("scan", "", "")
		fInput    = flag.String("input", "", "")
		fFormat   = flag.String("format", "txt", "")
		fOutput   = flag.String("output", "", "")
		fNoColor  = flag.Bool("no-color", false, "")
		fSelf     = flag.Bool("selftest", false, "")
		fDot      = flag.Bool("dot", false, "")
		fDiff     = flag.String("diff", "", "")
		fBaseline = flag.String("baseline", "", "")
		fFailOn   = flag.String("fail-on", "", "")
	)
	flag.Usage = usage
	flag.Parse()

	if *fNoColor {
		noColor = true
	}

	switch {
	case *fHelp || *fH:
		usage()
		return
	case *fVersion:
		fmt.Printf("%s %s — %s\n", APPNAME, VERSION, TAGLINE)
		fmt.Println("Author khaled.s.haddad | owlsec.org | Primary MITRE " + PRIMARY_MITRE)
		return
	case *fHowto:
		if noColor {
			fmt.Print(howtoText())
		} else {
			showHowto()
			fmt.Println()
		}
		return
	case *fDemo:
		runDemo()
		fmt.Println()
		return
	case *fSelf:
		os.Exit(runSelfTest())
	}

	scanTarget := *fScan
	if scanTarget == "" {
		scanTarget = *fInput
	}

	// CLI data operations that honor --format/--output
	if *fList {
		rep := buildReport("catalog", "catalog", catalogAsFindings())
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fStats {
		printCatalogStatsText()
		return
	}
	if *fSearch != "" {
		entries := searchCatalog(*fSearch)
		rep := buildReport("search:"+*fSearch, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fCat != "" {
		entries := filterByCategory(*fCat)
		rep := buildReport("category:"+*fCat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fPlat != "" {
		entries := filterByPlatform(*fPlat)
		rep := buildReport("platform:"+*fPlat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fID != "" {
		if e, ok := catalogByID(*fID); ok {
			rep := buildReport("entry:"+*fID, "catalog", entriesToFindings([]CatalogEntry{e}))
			writeOut(renderReport(rep, *fFormat), *fOutput)
		} else {
			fmt.Fprintln(os.Stderr, "no entry with ID "+*fID)
			os.Exit(1)
		}
		return
	}
	if *fDot {
		writeOut(lateralMapDOT(demoLateralMap()), *fOutput)
		return
	}
	if scanTarget != "" {
		fs, err := scanFile(scanTarget)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan error: "+err.Error())
			os.Exit(1)
		}
		// baseline suppression.
		if *fBaseline != "" {
			base, err := loadBaseline(*fBaseline)
			if err != nil {
				fmt.Fprintln(os.Stderr, "baseline error: "+err.Error())
				os.Exit(2)
			}
			before := len(fs)
			fs = applyBaseline(fs, base)
			fmt.Fprintf(os.Stderr, "baseline: suppressed %d of %d findings\n", before-len(fs), before)
		}
		// diff against a previous report.
		if *fDiff != "" {
			old, err := loadReport(*fDiff)
			if err != nil {
				fmt.Fprintln(os.Stderr, "diff error: "+err.Error())
				os.Exit(2)
			}
			added, resolved := diffFindings(old.Findings, fs)
			fmt.Printf("# scan diff vs %s\n", *fDiff)
			for _, f := range added {
				fmt.Printf("+ [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.Technique)
			}
			for _, f := range resolved {
				fmt.Printf("- [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.Technique)
			}
			fmt.Printf("# %d new, %d resolved\n", len(added), len(resolved))
			if len(added) > 0 {
				os.Exit(1)
			}
			return
		}
		rep := buildReport("scan", scanTarget, fs)
		writeOut(renderReport(rep, *fFormat), *fOutput)
		// severity gate.
		if *fFailOn != "" {
			if min, ok := sevRank[strings.ToLower(*fFailOn)]; ok && maxSeverity(fs) >= min {
				fmt.Fprintf(os.Stderr, "fail-on: a finding at or above %q severity was found\n", *fFailOn)
				os.Exit(3)
			}
		}
		return
	}
	if *fSigma {
		writeOut(generateSigma(), *fOutput)
		return
	}
	if *fCover {
		writeOut(attackCoverageText(), *fOutput)
		return
	}
	if *fPlan {
		rep := planReport()
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}

	// No flags -> interactive UI
	if noColor && !isatty() {
		// Non-interactive without flags: print help so piping is useful.
		usage()
		return
	}
	mainMenu()
}

// entriesToFindings converts catalog entries into findings for export.
func entriesToFindings(entries []CatalogEntry) []Finding {
	var fs []Finding
	for _, e := range entries {
		fs = append(fs, Finding{
			RuleID: e.ID, Title: e.Name, Severity: e.Severity,
			Score: sevWeight[strings.ToLower(e.Severity)], Tactic: e.Tactic,
			Technique: e.Technique, Detail: e.Summary,
			Detection: strings.Join(e.Detection, "; "), Refs: e.Refs,
			Fprint: fingerprint(e.ID),
		})
	}
	return fs
}

// printCatalogStatsText prints catalog stats as plain text (CLI).
func printCatalogStatsText() {
	bySev := map[string]int{}
	byCat := map[string]int{}
	markers := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		markers += len(e.Markers)
	}
	fmt.Printf("%s catalog: %d entries, %d markers, %d categories\n", APPNAME, len(catalog), markers, len(byCat))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			fmt.Printf("  %-9s %d\n", s, bySev[s])
		}
	}
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("  [cat] %-28s %d\n", c, byCat[c])
	}
}

// ====================================================================
//  SELF-TEST — verifies the catalog, scanner, search and exporters.
// ====================================================================

func runSelfTest() int {
	banner()
	fmt.Println("  " + col("⬡  Self-Test — "+APPNAME+" engine", B+CY))
	rule()
	fmt.Println()
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W))
		}
	}

	// catalog integrity.
	check("catalog is non-empty", len(catalog) > 0)
	idset := map[string]bool{}
	fieldsOK, dup := true, false
	for _, e := range catalog {
		if e.ID == "" || e.Name == "" || e.Category == "" || e.Technique == "" {
			fieldsOK = false
		}
		if idset[e.ID] {
			dup = true
		}
		idset[e.ID] = true
	}
	check("every entry has ID/Name/Category/Technique", fieldsOK)
	check("catalog IDs are unique", !dup)

	// fingerprint.
	check("fingerprint is deterministic", fingerprint("a", "b") == fingerprint("a", "b"))
	check("fingerprint differs on input", fingerprint("a", "b") != fingerprint("a", "c"))
	check("fingerprint is 16 hex chars", len(fingerprint("x")) == 16)

	// severity weights are strictly ordered.
	check("sevWeight ordered crit>high>med>low>info",
		sevWeight["critical"] > sevWeight["high"] &&
			sevWeight["high"] > sevWeight["medium"] &&
			sevWeight["medium"] > sevWeight["low"] &&
			sevWeight["low"] > sevWeight["info"])

	// search.
	check("searchCatalog(\"\") = nil", searchCatalog("") == nil)
	check("searchCatalog(\"smb\") finds entries", len(searchCatalog("smb")) > 0)
	check("searchCatalog(\"zzzznomatch\") = empty", len(searchCatalog("zzzznomatch")) == 0)
	check("filterByCategory(Lateral) non-empty", len(filterByCategory("Lateral")) > 0)

	// scanner: feed a synthetic log carrying known markers.
	sample := "2024-01-01 host$ psexec \\\\TARGET cmd.exe\nInvoke-WmiMethod -Class Win32_Process -Name Create\nnothing here\n"
	fs := scanReader("selftest.log", strings.NewReader(sample))
	check("scanReader detects marker lines", len(fs) >= 1)
	markedSMB := false
	for _, f := range fs {
		if strings.Contains(strings.ToLower(f.Technique), "t1021") || strings.Contains(strings.ToLower(f.RuleID), "smb") {
			markedSMB = true
		}
	}
	check("scanner maps a PsExec line to an SMB/T1021 finding", markedSMB)

	// exporters: every format renders, JSON is valid.
	rep := buildReport("selftest", "selftest.log", fs)
	for _, fmtName := range []string{"txt", "md", "json", "csv", "sarif"} {
		out := renderReport(rep, fmtName)
		check("renderReport("+fmtName+") produces output", len(strings.TrimSpace(out)) > 0)
	}
	var js interface{}
	check("JSON export is valid JSON", json.Unmarshal([]byte(renderReport(rep, "json")), &js) == nil)
	var sarif map[string]interface{}
	check("SARIF export is valid JSON", json.Unmarshal([]byte(renderReport(rep, "sarif")), &sarif) == nil)

	// sigma + coverage.
	check("generateSigma produces rules", len(strings.TrimSpace(generateSigma())) > 0)
	check("attackCoverageText produces a matrix", len(strings.TrimSpace(attackCoverageText())) > 0)

	// helpers.
	check("stripANSI removes colour", stripANSI(col("hi", CY)) == "hi")
	check("visw counts runes", visw("abc") == 3)

	// v1.1: DOT export.
	dot := lateralMapDOT(demoLateralMap())
	check("DOT export is a digraph", strings.HasPrefix(dot, "digraph lateral {") && strings.Contains(dot, "->"))

	// v1.1: diff by fingerprint.
	a := []Finding{{Fprint: "x", Title: "A"}, {Fprint: "y", Title: "B"}}
	b := []Finding{{Fprint: "y", Title: "B"}, {Fprint: "z", Title: "C"}}
	added, resolved := diffFindings(a, b)
	check("diffFindings detects 1 new (z)", len(added) == 1 && added[0].Fprint == "z")
	check("diffFindings detects 1 resolved (x)", len(resolved) == 1 && resolved[0].Fprint == "x")

	// v1.1: baseline suppression.
	base := map[string]bool{"y": true}
	kept := applyBaseline(b, base)
	check("applyBaseline removes suppressed fingerprints", len(kept) == 1 && kept[0].Fprint == "z")
	check("applyBaseline with empty set is a no-op", len(applyBaseline(b, nil)) == len(b))

	// v1.1: severity gate.
	gateFs := []Finding{{Severity: "low"}, {Severity: "high"}}
	check("maxSeverity picks the highest rank", maxSeverity(gateFs) == sevRank["high"])
	check("maxSeverity of empty = 0", maxSeverity(nil) == 0)

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}
