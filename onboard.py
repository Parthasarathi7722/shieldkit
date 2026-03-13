#!/usr/bin/env python3
"""
ShieldKit Onboarding Wizard — Interactive CLI for tool and credential setup.
Supports: --check, --add <tool>, --list, --tier <name>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

BASE = Path(__file__).resolve().parent

# ── Tool Definitions ─────────────────────────────────────────────

@dataclass
class ToolDef:
    name: str
    binary: str
    category: str
    install_cmd: str
    env_vars: list[tuple[str, str, bool]]  # (name, description, required)
    docs: str


TOOLS: dict[str, ToolDef] = {
    "syft": ToolDef(
        name="Syft", binary="syft", category="SBOM",
        install_cmd="curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        env_vars=[], docs="https://github.com/anchore/syft",
    ),
    "grype": ToolDef(
        name="Grype", binary="grype", category="SCA",
        install_cmd="curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        env_vars=[("GRYPE_DB_AUTO_UPDATE", "Auto-update vulnerability DB (true/false)", False)],
        docs="https://github.com/anchore/grype",
    ),
    "trivy": ToolDef(
        name="Trivy", binary="trivy", category="Container Scanning",
        install_cmd="curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
        env_vars=[], docs="https://github.com/aquasecurity/trivy",
    ),
    "nuclei": ToolDef(
        name="Nuclei", binary="nuclei", category="URL Scanning",
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        env_vars=[("NUCLEI_TEMPLATES_DIR", "Custom templates directory", False)],
        docs="https://github.com/projectdiscovery/nuclei",
    ),
    "prowler": ToolDef(
        name="Prowler", binary="prowler", category="Cloud Security",
        install_cmd="pip install prowler",
        env_vars=[
            ("AWS_PROFILE", "AWS CLI profile name", False),
            ("AWS_REGION", "AWS region (default: us-east-1)", False),
            ("AZURE_SUBSCRIPTION_ID", "Azure subscription ID", False),
            ("AZURE_TENANT_ID", "Azure tenant ID", False),
            ("GCP_PROJECT_ID", "GCP project ID", False),
        ],
        docs="https://github.com/prowler-cloud/prowler",
    ),
    "checkov": ToolDef(
        name="Checkov", binary="checkov", category="IaC Scanning",
        install_cmd="pip install checkov",
        env_vars=[("CHECKOV_API_KEY", "Bridgecrew API key (optional, for enhanced checks)", False)],
        docs="https://github.com/bridgecrewio/checkov",
    ),
    "scoutsuite": ToolDef(
        name="ScoutSuite", binary="scout", category="Cloud Auditing",
        install_cmd="pip install scoutsuite",
        env_vars=[
            ("AWS_PROFILE", "AWS CLI profile name", False),
            ("AZURE_SUBSCRIPTION_ID", "Azure subscription ID", False),
            ("GCP_PROJECT_ID", "GCP project ID", False),
        ],
        docs="https://github.com/nccgroup/ScoutSuite",
    ),
}

TIERS = {
    "starter": ["syft", "grype", "trivy"],
    "scanner": ["syft", "grype", "trivy", "nuclei", "checkov"],
    "cloud": ["syft", "grype", "trivy", "nuclei", "checkov", "prowler", "scoutsuite"],
}


# ── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ShieldKit Onboarding Wizard")
    parser.add_argument("--check", action="store_true", help="Check all tool installations")
    parser.add_argument("--add", type=str, help="Add/configure a specific tool")
    parser.add_argument("--list", action="store_true", help="List all available tools")
    parser.add_argument("--tier", type=str, choices=["starter", "scanner", "cloud"],
                        help="Configure tools for a tier")
    args = parser.parse_args()

    print_banner()

    if args.check:
        check_all()
    elif args.add:
        add_tool(args.add)
    elif args.list:
        list_tools()
    elif args.tier:
        setup_tier(args.tier)
    else:
        interactive_wizard()


def print_banner():
    print("\n" + "=" * 60)
    print("  🛡️  ShieldKit Onboarding Wizard")
    print("  Security scanning, cloud posture, and log analytics")
    print("=" * 60 + "\n")


def check_all():
    """Check installation status of all tools."""
    print("Checking tool installations...\n")
    for key, tool in TOOLS.items():
        path = shutil.which(tool.binary)
        if path:
            version = get_version(tool.binary)
            print(f"  ✅ {tool.name:12s} │ {version:30s} │ {path}")
        else:
            print(f"  ❌ {tool.name:12s} │ Not installed")
            print(f"     Install: {tool.install_cmd}")
    print()


def list_tools():
    """List all available tools with categories."""
    print(f"{'Tool':12s} │ {'Category':20s} │ {'Docs'}")
    print("─" * 70)
    for key, tool in TOOLS.items():
        print(f"{tool.name:12s} │ {tool.category:20s} │ {tool.docs}")
    print(f"\nTiers:")
    for tier, tools in TIERS.items():
        print(f"  {tier:10s}: {', '.join(tools)}")
    print()


def add_tool(name: str):
    """Configure a single tool."""
    if name not in TOOLS:
        print(f"Unknown tool: {name}. Available: {', '.join(TOOLS.keys())}")
        return

    tool = TOOLS[name]
    print(f"Configuring {tool.name} ({tool.category})...\n")

    path = shutil.which(tool.binary)
    if not path:
        print(f"  ⚠️  {tool.name} not found. Install with:")
        print(f"     {tool.install_cmd}\n")
        install = input("  Install now? [y/N]: ").strip().lower()
        if install == "y":
            os.system(tool.install_cmd)
    else:
        print(f"  ✅ Found at {path}")

    env_vars = collect_env_vars(tool)
    if env_vars:
        write_env(env_vars)
        print(f"\n  ✅ Configuration saved to .env")


def setup_tier(tier: str):
    """Set up all tools for a tier."""
    tools = TIERS.get(tier, [])
    print(f"Setting up {tier.upper()} tier ({len(tools)} tools)...\n")

    all_env: dict[str, str] = {}
    for name in tools:
        tool = TOOLS[name]
        path = shutil.which(tool.binary)
        status = f"✅ installed" if path else f"❌ missing"
        print(f"  {tool.name:12s} │ {status}")

        env_vars = collect_env_vars(tool, silent=True)
        all_env.update(env_vars)

    # AI config
    print("\n  AI Provider Configuration:")
    provider = input("  Provider (anthropic/openai/local) [anthropic]: ").strip() or "anthropic"
    api_key = getpass("  API Key: ").strip()
    all_env["AI_PROVIDER"] = provider
    all_env["AI_API_KEY"] = api_key
    all_env["SHIELDKIT_MODE"] = "live" if api_key else "mock"

    if provider == "local":
        base_url = input("  Base URL (e.g. http://localhost:11434/v1): ").strip()
        model = input("  Model name: ").strip()
        all_env["AI_BASE_URL"] = base_url
        all_env["AI_MODEL"] = model

    write_env(all_env)
    print(f"\n✅ {tier.upper()} tier configured. Run: source .env && uvicorn shieldkit.server:app")


def interactive_wizard():
    """Full interactive setup wizard."""
    print("Choose a deployment tier:\n")
    print("  1. Starter (Free)    — Syft + Grype + Trivy")
    print("  2. Full Scanner      — Starter + Nuclei + Checkov")
    print("  3. Cloud Security    — Full Scanner + Prowler + ScoutSuite")
    print("  4. Custom            — Pick your own tools\n")

    choice = input("Select tier [1-4]: ").strip()
    tier_map = {"1": "starter", "2": "scanner", "3": "cloud"}

    if choice in tier_map:
        setup_tier(tier_map[choice])
    elif choice == "4":
        print("\nAvailable tools:")
        for i, (key, tool) in enumerate(TOOLS.items(), 1):
            print(f"  {i}. {tool.name:12s} ({tool.category})")
        selections = input("\nEnter tool numbers (comma-separated): ").strip()
        tool_keys = list(TOOLS.keys())
        selected = []
        for s in selections.split(","):
            idx = int(s.strip()) - 1
            if 0 <= idx < len(tool_keys):
                selected.append(tool_keys[idx])

        all_env: dict[str, str] = {}
        for name in selected:
            env_vars = collect_env_vars(TOOLS[name])
            all_env.update(env_vars)

        print("\n  AI Provider Configuration:")
        provider = input("  Provider (anthropic/openai/local) [anthropic]: ").strip() or "anthropic"
        api_key = getpass("  API Key: ").strip()
        all_env["AI_PROVIDER"] = provider
        all_env["AI_API_KEY"] = api_key
        all_env["SHIELDKIT_MODE"] = "live" if api_key else "mock"

        write_env(all_env)
        print(f"\n✅ Custom configuration saved.")
    else:
        print("Invalid selection.")


# ── Helpers ──────────────────────────────────────────────────────

def collect_env_vars(tool: ToolDef, silent: bool = False) -> dict[str, str]:
    """Collect environment variables for a tool."""
    env = {}
    for var_name, desc, required in tool.env_vars:
        if os.environ.get(var_name):
            if not silent:
                print(f"  {var_name} already set")
            continue
        if silent:
            continue
        prompt = f"  {var_name} ({desc})"
        if required:
            prompt += " [REQUIRED]"
        else:
            prompt += " [optional, press Enter to skip]"
        prompt += ": "

        if "key" in var_name.lower() or "secret" in var_name.lower() or "token" in var_name.lower():
            val = getpass(prompt).strip()
        else:
            val = input(prompt).strip()

        if val:
            env[var_name] = val
    return env


def write_env(env_vars: dict[str, str]):
    """Write environment variables to .env file."""
    env_file = BASE / ".env"

    # Backup existing
    if env_file.exists():
        backup = BASE / f".env.backup.{int(__import__('time').time())}"
        shutil.copy2(env_file, backup)
        existing = env_file.read_text()
    else:
        existing = ""

    # Merge
    existing_vars = {}
    for line in existing.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            existing_vars[k.strip()] = v.strip().strip("\"'")

    existing_vars.update(env_vars)

    with env_file.open("w") as f:
        f.write("# ShieldKit Configuration\n")
        f.write(f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}\n\n")

        sections = {
            "AI": ["AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_BASE_URL"],
            "Mode": ["SHIELDKIT_MODE", "DUCKDB_PATH", "LOG_RETENTION_DAYS"],
            "AWS": ["AWS_PROFILE", "AWS_REGION"],
            "Azure": ["AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID"],
            "GCP": ["GCP_PROJECT_ID"],
            "Tools": ["GRYPE_DB_AUTO_UPDATE", "NUCLEI_TEMPLATES_DIR", "CHECKOV_API_KEY"],
        }

        written = set()
        for section, keys in sections.items():
            section_vars = {k: existing_vars[k] for k in keys if k in existing_vars}
            if section_vars:
                f.write(f"# ── {section} ──\n")
                for k, v in section_vars.items():
                    f.write(f'{k}="{v}"\n')
                    written.add(k)
                f.write("\n")

        # Write remaining
        remaining = {k: v for k, v in existing_vars.items() if k not in written}
        if remaining:
            f.write("# ── Other ──\n")
            for k, v in remaining.items():
                f.write(f'{k}="{v}"\n')


def get_version(binary: str) -> str:
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
        return (result.stdout or result.stderr).strip().split("\n")[0][:30]
    except Exception:
        return "version unknown"


if __name__ == "__main__":
    main()
