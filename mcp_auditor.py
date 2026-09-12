import json
import re
import sys
from datetime import datetime
from pathlib import Path

# Allow importing common modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(
    0,
    str(PROJECT_ROOT)
)

from common.ollama_client import ask_ollama
from common.prompts import MCP_SECURITY_PROMPT


# ============================================================
# Static security indicators
# ============================================================

SUSPICIOUS_PATTERNS = {

    "prompt_injection": [
        r"ignore previous instructions",
        r"ignore your previous instructions",
        r"disregard previous instructions",
        r"ignore all previous",
        r"system message",
        r"reveal.*secret",
        r"disclose.*private",
        r"send.*private information",
    ],

    "secret_access": [
        r"api[_-]?key",
        r"secret",
        r"password",
        r"token",
        r"credential",
        r"private[_-]?key",
    ],

    "external_communication": [
        r"send_email",
        r"requests\.",
        r"httpx\.",
        r"urllib",
        r"socket\.",
        r"smtp",
        r"webhook",
    ],

    "destructive_operations": [
        r"delete",
        r"unlink",
        r"remove",
        r"shutil\.rmtree",
        r"os\.remove",
    ],

    "shell_execution": [
        r"subprocess",
        r"os\.system",
        r"powershell",
        r"cmd\.exe",
        r"shell\s*=\s*True",
    ],

    "file_access": [
        r"open\(",
        r"Path\(",
        r"read_text",
        r"write_text",
        r"unlink",
    ],
}


# ============================================================
# Static pattern detection
# ============================================================

def detect_patterns(source):

    findings = []

    lines = source.splitlines()

    for category, patterns in SUSPICIOUS_PATTERNS.items():

        for pattern in patterns:

            regex = re.compile(
                pattern,
                re.IGNORECASE
            )

            for line_number, line in enumerate(
                lines,
                start=1
            ):

                if regex.search(line):

                    findings.append({
                        "category": category,
                        "line": line_number,
                        "evidence": line.strip(),
                    })

    return findings


# ============================================================
# Extract FastMCP tools
# ============================================================

def extract_tools(source):

    tools = []

    pattern = re.compile(
        r"@mcp\.tool\(\)\s*"
        r"def\s+([A-Za-z_][A-Za-z0-9_]*)"
        r"\s*\((.*?)\)"
        r"(?:\s*->\s*([^:]+))?:",
        re.DOTALL,
    )

    for match in pattern.finditer(source):

        name = match.group(1)

        arguments = match.group(2)

        return_type = match.group(3)

        start = match.end()

        remainder = source[
            start:start + 3000
        ]

        docstring = ""

        doc_match = re.search(
            r'"""(.*?)"""',
            remainder,
            re.DOTALL
        )

        if doc_match:

            docstring = (
                doc_match.group(1)
                .strip()
            )

        tools.append({
            "name": name,
            "arguments": arguments.strip(),
            "return_type": (
                return_type.strip()
                if return_type
                else None
            ),
            "description": docstring,
        })

    return tools


# ============================================================
# Build evidence
# ============================================================

def build_static_report(source):

    tools = extract_tools(source)

    patterns = detect_patterns(source)

    return {
        "scan_type": "Static MCP Source Audit",
        "timestamp": datetime.now().isoformat(),
        "line_count": len(source.splitlines()),
        "source_length": len(source),
        "tool_count": len(tools),
        "tools": tools,
        "static_indicators": patterns,
    }


# ============================================================
# Build Foundation-Sec prompt
# ============================================================

def build_prompt(
    source,
    static_report
):

    return f"""
{MCP_SECURITY_PROMPT}

============================================================
STATIC ANALYSIS
============================================================

The static analyzer found the following indicators.

These are NOT automatically vulnerabilities.

Validate each indicator against the source.

{json.dumps(static_report, indent=2)}

============================================================
MCP SOURCE CODE
============================================================

{source}

============================================================
SPECIAL ANALYSIS REQUIREMENTS
============================================================

Analyze relationships between tools.

Pay particular attention to flows involving:

UNTRUSTED CONTENT
        +
SENSITIVE DATA
        +
EXTERNAL SIDE EFFECT

For example:

untrusted MCP output
        ->
AI agent
        ->
sensitive-data tool
        ->
external communication

Only report a toxic flow when the supplied code supports it.

Also distinguish:

1. Dangerous capability
2. Security weakness
3. Potential vulnerability
4. Confirmed vulnerability
5. Actual exploitation

The source represents a LOCAL security lab.

Do not execute it.
Do not attack external systems.
Do not claim simulated actions actually happened.

============================================================
OUTPUT
============================================================

Generate a professional security assessment suitable for
a developer/security engineer.

Use concise evidence-based findings.
"""


# ============================================================
# Main scanner
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage:\n"
            "  python mcp_auditor.py <mcp_server.py>"
        )

        sys.exit(1)


    target = Path(
        sys.argv[1]
    ).resolve()


    if not target.exists():

        print(
            f"ERROR: File not found: {target}"
        )

        sys.exit(1)


    if target.suffix.lower() != ".py":

        print(
            "WARNING: Target does not have a .py extension."
        )


    print()
    print("=" * 70)
    print("             MCP SECURITY AUDITOR")
    print("             Foundation-Sec-8B")
    print("=" * 70)
    print()

    print(f"Target: {target}")


    # --------------------------------------------------------
    # Read source
    # --------------------------------------------------------

    source = target.read_text(
        encoding="utf-8"
    )

    print(
        f"Lines:  {len(source.splitlines())}"
    )


    # --------------------------------------------------------
    # Extract tools
    # --------------------------------------------------------

    print()
    print("[1/3] Extracting MCP tools...")
    print()

    tools = extract_tools(source)

    if tools:

        for tool in tools:

            print(
                f"  [+] {tool['name']}"
            )

    else:

        print(
            "  [!] No FastMCP tools detected."
        )


    # --------------------------------------------------------
    # Static analysis
    # --------------------------------------------------------

    print()
    print("[2/3] Running static security analysis...")
    print()

    static_report = build_static_report(
        source
    )

    print(
        "  [+] Security indicators: "
        f"{len(static_report['static_indicators'])}"
    )


    # --------------------------------------------------------
    # LLM analysis
    # --------------------------------------------------------

    print()
    print("[3/3] Sending evidence to Foundation-Sec...")
    print()

    prompt = build_prompt(
        source,
        static_report
    )

    try:

        report = ask_ollama(
            prompt
        )

    except Exception as error:

        print()
        print(
            "ERROR: Ollama request failed."
        )

        print(
            str(error)
        )

        sys.exit(1)


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("             MCP SECURITY ASSESSMENT")
    print("=" * 70)
    print()

    print(report)


    # --------------------------------------------------------
    # Save report
    # --------------------------------------------------------

    reports_dir = (
        PROJECT_ROOT
        / "reports"
        / "mcp"
    )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_file = (
        reports_dir
        / f"{target.stem}_security_{timestamp}.md"
    )

    report_file.write_text(
        report,
        encoding="utf-8"
    )


    # Save machine-readable evidence too
    evidence_file = (
        reports_dir
        / f"{target.stem}_evidence_{timestamp}.json"
    )

    evidence_file.write_text(
        json.dumps(
            static_report,
            indent=4
        ),
        encoding="utf-8"
    )


    print()
    print("=" * 70)
    print("Reports saved:")
    print(report_file)
    print(evidence_file)
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()