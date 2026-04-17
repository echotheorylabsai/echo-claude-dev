#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


PROMPT_RULE_ALLOWED_FIELDS = {
    "id",
    "category",
    "severity",
    "description",
    "pattern",
    "caseInsensitive",
    "enabled",
    "engine",
}
PROMPT_DEFAULT_ALLOWED_FIELDS = {"severity", "caseInsensitive", "enabled", "engine"}
TOOL_RULE_ALLOWED_FIELDS = {
    "id",
    "tool",
    "targetField",
    "pattern",
    "reason",
    "action",
    "caseInsensitive",
    "enabled",
}
TOOL_DEFAULT_ALLOWED_FIELDS = {"tool", "targetField", "action", "caseInsensitive", "enabled"}
# Claude Code PascalCase tool names
VALID_TOOLS = {"Bash", "Edit", "Write", "NotebookEdit"}
# Supported target fields (path covers Edit/Write/NotebookEdit; command covers Bash)
VALID_TARGET_FIELDS = {"command", "path", "file_path"}
VALID_ACTIONS = {"deny"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile secure-claude YAML rule config into runtime JSON"
    )
    parser.add_argument(
        "--mode",
        choices=["shipped", "overrides", "both"],
        default="both",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify generated JSON is up to date instead of writing it",
    )
    parser.add_argument("--plugin-root", help="Override the secure-claude plugin root")
    parser.add_argument("--prompt-source", help="Override the prompt YAML source file")
    parser.add_argument("--tool-source", help="Override the tool YAML source file")
    parser.add_argument(
        "--indirect-source", help="Override the indirect injection YAML source file"
    )
    parser.add_argument("--override-source", help="Override the local overrides YAML source file")
    parser.add_argument("--output-dir", help="Override the generated JSON output directory")
    return parser.parse_args()


def resolve_plugin_root(args: argparse.Namespace) -> Path:
    if args.plugin_root:
        return Path(args.plugin_root).expanduser().resolve()
    env_root = os.environ.get("SECURE_CLAUDE_PLUGIN_ROOT", "")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def load_yaml_file(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{label}: unable to read {path}: {exc}") from exc

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{label}: invalid YAML in {path}: {exc}") from exc

    if document is None:
        return {}
    if not isinstance(document, dict):
        raise ConfigError(f"{label}: expected top-level mapping in {path}")
    return document


def ensure_mapping(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{label}: expected mapping")
    return value


def ensure_list(value: Any, label: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{label}: expected list")
    return value


def ensure_unknown_keys_absent(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown_keys = sorted(set(mapping) - allowed)
    if unknown_keys:
        raise ConfigError(f"{label}: unknown field(s): {', '.join(unknown_keys)}")


def validate_regex(pattern: str, label: str, engine: str = "posix") -> None:
    if engine == "pcre":
        result = subprocess.run(
            ["perl", "-e", "my $p = <STDIN>; chomp $p; qr/$p/"],
            input=pattern + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip() or "perl rejected the PCRE pattern"
            raise ConfigError(f"{label}: invalid PCRE pattern {pattern!r}: {stderr}")
        return

    result = subprocess.run(
        ["grep", "-E", "--", pattern, "/dev/null"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 2:
        stderr = result.stderr.strip() or "grep -E rejected the pattern"
        raise ConfigError(f"{label}: invalid grep -E pattern {pattern!r}: {stderr}")


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label}: expected non-empty string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{label}: expected boolean")
    return value


def require_number(value: Any, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{label}: expected number")
    return float(value)


def validate_unique_ids(rules: Iterable[dict[str, Any]], label: str) -> None:
    seen: set[str] = set()
    for rule in rules:
        rule_id = rule["id"]
        if rule_id in seen:
            raise ConfigError(f"{label}: duplicate rule id: {rule_id}")
        seen.add(rule_id)


def normalize_prompt_defaults(defaults: dict[str, Any], label: str) -> dict[str, Any]:
    ensure_unknown_keys_absent(defaults, PROMPT_DEFAULT_ALLOWED_FIELDS, label)
    normalized: dict[str, Any] = {}
    if "severity" in defaults:
        normalized["severity"] = require_number(defaults["severity"], f"{label}.severity")
    if "caseInsensitive" in defaults:
        normalized["caseInsensitive"] = require_bool(
            defaults["caseInsensitive"], f"{label}.caseInsensitive"
        )
    if "enabled" in defaults:
        normalized["enabled"] = require_bool(defaults["enabled"], f"{label}.enabled")
    if "engine" in defaults:
        engine = require_string(defaults["engine"], f"{label}.engine")
        if engine not in ("posix", "pcre"):
            raise ConfigError(f"{label}.engine: unsupported engine {engine}")
        normalized["engine"] = engine
    return normalized


def normalize_tool_defaults(defaults: dict[str, Any], label: str) -> dict[str, Any]:
    ensure_unknown_keys_absent(defaults, TOOL_DEFAULT_ALLOWED_FIELDS, label)
    normalized: dict[str, Any] = {}
    if "tool" in defaults:
        tool = require_string(defaults["tool"], f"{label}.tool")
        if tool not in VALID_TOOLS:
            raise ConfigError(
                f"{label}.tool: unsupported tool {tool!r} (valid: {sorted(VALID_TOOLS)})"
            )
        normalized["tool"] = tool
    if "targetField" in defaults:
        target_field = require_string(defaults["targetField"], f"{label}.targetField")
        if target_field not in VALID_TARGET_FIELDS:
            raise ConfigError(
                f"{label}.targetField: unsupported targetField {target_field!r} (valid: {sorted(VALID_TARGET_FIELDS)})"
            )
        normalized["targetField"] = target_field
    if "action" in defaults:
        action = require_string(defaults["action"], f"{label}.action")
        if action not in VALID_ACTIONS:
            raise ConfigError(f"{label}.action: unsupported action {action}")
        normalized["action"] = action
    if "caseInsensitive" in defaults:
        normalized["caseInsensitive"] = require_bool(
            defaults["caseInsensitive"], f"{label}.caseInsensitive"
        )
    if "enabled" in defaults:
        normalized["enabled"] = require_bool(defaults["enabled"], f"{label}.enabled")
    return normalized


def normalize_prompt_rule(rule: dict[str, Any], label: str) -> dict[str, Any]:
    ensure_unknown_keys_absent(rule, PROMPT_RULE_ALLOWED_FIELDS, label)
    engine = rule.get("engine", "posix")
    if isinstance(engine, str) and engine not in ("posix", "pcre"):
        raise ConfigError(f"{label}.engine: unsupported engine {engine}")
    normalized = {
        "id": require_string(rule.get("id"), f"{label}.id"),
        "category": require_string(rule.get("category"), f"{label}.category"),
        "severity": require_number(rule.get("severity"), f"{label}.severity"),
        "description": require_string(rule.get("description"), f"{label}.description"),
        "pattern": require_string(rule.get("pattern"), f"{label}.pattern"),
        "caseInsensitive": require_bool(rule.get("caseInsensitive"), f"{label}.caseInsensitive"),
        "enabled": require_bool(rule.get("enabled"), f"{label}.enabled"),
    }
    if engine != "posix":
        normalized["engine"] = engine
    validate_regex(normalized["pattern"], label, engine=engine)
    return normalized


def normalize_tool_rule(rule: dict[str, Any], label: str) -> dict[str, Any]:
    ensure_unknown_keys_absent(rule, TOOL_RULE_ALLOWED_FIELDS, label)
    tool = require_string(rule.get("tool"), f"{label}.tool")
    if tool not in VALID_TOOLS:
        raise ConfigError(f"{label}.tool: unsupported tool {tool!r} (valid: {sorted(VALID_TOOLS)})")
    target_field = require_string(rule.get("targetField"), f"{label}.targetField")
    if target_field not in VALID_TARGET_FIELDS:
        raise ConfigError(
            f"{label}.targetField: unsupported targetField {target_field!r} (valid: {sorted(VALID_TARGET_FIELDS)})"
        )
    action = require_string(rule.get("action"), f"{label}.action")
    if action not in VALID_ACTIONS:
        raise ConfigError(f"{label}.action: unsupported action {action}")
    normalized = {
        "id": require_string(rule.get("id"), f"{label}.id"),
        "tool": tool,
        "targetField": target_field,
        "pattern": require_string(rule.get("pattern"), f"{label}.pattern"),
        "reason": require_string(rule.get("reason"), f"{label}.reason"),
        "action": action,
        "caseInsensitive": require_bool(rule.get("caseInsensitive"), f"{label}.caseInsensitive"),
        "enabled": require_bool(rule.get("enabled"), f"{label}.enabled"),
    }
    validate_regex(normalized["pattern"], label)
    return normalized


def compile_shipped_rules(
    document: dict[str, Any],
    group_key: str,
    normalize_defaults_fn: Any,
    normalize_rule_fn: Any,
    label: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Generic compiler for shipped rule configs (prompt, tool, indirect injection)."""
    ensure_unknown_keys_absent(document, {"defaults", group_key}, label)
    global_defaults = normalize_defaults_fn(
        ensure_mapping(document.get("defaults"), f"{label}.defaults"),
        f"{label}.defaults",
    )
    groups = ensure_mapping(document.get(group_key), f"{label}.{group_key}")
    rules: list[dict[str, Any]] = []
    for group_name, group_value in groups.items():
        group_label = f"{label}.{group_key}.{group_name}"
        group_mapping = ensure_mapping(group_value, group_label)
        ensure_unknown_keys_absent(group_mapping, {"defaults", "rules"}, group_label)
        group_defaults = normalize_defaults_fn(
            ensure_mapping(group_mapping.get("defaults"), f"{group_label}.defaults"),
            f"{group_label}.defaults",
        )
        inject = {"category": group_name} if group_key == "categories" else {}
        for index, raw_rule in enumerate(
            ensure_list(group_mapping.get("rules"), f"{group_label}.rules")
        ):
            rule_label = f"{group_label}.rules[{index}]"
            rule_mapping = ensure_mapping(raw_rule, rule_label)
            merged_rule = {
                **global_defaults,
                **group_defaults,
                **inject,
                **rule_mapping,
            }
            rules.append(normalize_rule_fn(merged_rule, rule_label))
    validate_unique_ids(rules, label)
    return rules, global_defaults


def compile_shipped_prompt_rules(
    document: dict[str, Any], label: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return compile_shipped_rules(
        document, "categories", normalize_prompt_defaults, normalize_prompt_rule, label
    )


def compile_shipped_tool_rules(
    document: dict[str, Any], label: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return compile_shipped_rules(
        document, "groups", normalize_tool_defaults, normalize_tool_rule, label
    )


def compile_overrides(
    document: dict[str, Any],
    key: str,
    defaults: dict[str, Any],
    shipped_ids: set[str],
    normalize_rule_fn: Any,
    label: str,
) -> list[dict[str, Any]]:
    """Generic compiler for local override rules (prompt, tool, indirect injection)."""
    raw_rules = ensure_list(document.get(key), f"{label}.{key}")
    rules: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(raw_rules):
        rule_label = f"{label}.{key}[{index}]"
        rule_mapping = ensure_mapping(raw_rule, rule_label)
        merged_rule = {**defaults, **rule_mapping}
        normalized = normalize_rule_fn(merged_rule, rule_label)
        if normalized["id"] in shipped_ids:
            raise ConfigError(
                f"{rule_label}: override may not modify shipped rule id: {normalized['id']}"
            )
        rules.append(normalized)
    validate_unique_ids(rules, f"{label}.{key}")
    return rules


def compile_prompt_overrides(
    document: dict[str, Any],
    defaults: dict[str, Any],
    shipped_ids: set[str],
    label: str,
) -> list[dict[str, Any]]:
    return compile_overrides(
        document, "promptPatterns", defaults, shipped_ids, normalize_prompt_rule, label
    )


def compile_tool_overrides(
    document: dict[str, Any],
    defaults: dict[str, Any],
    shipped_ids: set[str],
    label: str,
) -> list[dict[str, Any]]:
    return compile_overrides(
        document, "toolRules", defaults, shipped_ids, normalize_tool_rule, label
    )


def render_json(rules: list[dict[str, Any]]) -> str:
    return json.dumps(rules, indent=2, sort_keys=True) + "\n"


def write_or_check_output(output_path: Path, content: str, check: bool, label: str) -> None:
    if check:
        if not output_path.is_file():
            raise ConfigError(f"{label}: generated artifact missing: {output_path}")
        existing = output_path.read_text(encoding="utf-8")
        if existing != content:
            raise ConfigError(f"{label}: generated artifact is stale: {output_path}")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def remove_if_present(path: Path) -> None:
    if path.exists():
        path.unlink()


def compile_shipped(args: argparse.Namespace, plugin_root: Path) -> None:
    prompt_source = (
        Path(args.prompt_source).expanduser().resolve()
        if args.prompt_source
        else plugin_root / "hooks/config/user-prompt-threats.yaml"
    )
    tool_source = (
        Path(args.tool_source).expanduser().resolve()
        if args.tool_source
        else plugin_root / "hooks/config/tool-rules.yaml"
    )
    indirect_source = (
        Path(args.indirect_source).expanduser().resolve()
        if args.indirect_source
        else plugin_root / "hooks/config/indirect-injection-patterns.yaml"
    )
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else plugin_root / "hooks/config/generated"
    )

    prompt_rules, _ = compile_shipped_prompt_rules(
        load_yaml_file(prompt_source, "prompt rules"), "prompt rules"
    )
    tool_rules, _ = compile_shipped_tool_rules(
        load_yaml_file(tool_source, "tool rules"), "tool rules"
    )

    write_or_check_output(
        output_dir / "user-prompt-threats.json",
        render_json(prompt_rules),
        args.check,
        "prompt rules",
    )
    write_or_check_output(
        output_dir / "tool-rules.json",
        render_json(tool_rules),
        args.check,
        "tool rules",
    )

    if indirect_source.exists():
        indirect_rules, _ = compile_shipped_prompt_rules(
            load_yaml_file(indirect_source, "indirect injection rules"),
            "indirect injection rules",
        )
        write_or_check_output(
            output_dir / "indirect-injection-patterns.json",
            render_json(indirect_rules),
            args.check,
            "indirect injection rules",
        )


def compile_local(args: argparse.Namespace, plugin_root: Path) -> None:
    if args.check:
        raise ConfigError("--check is only supported in shipped mode")

    prompt_source = (
        Path(args.prompt_source).expanduser().resolve()
        if args.prompt_source
        else plugin_root / "hooks/config/user-prompt-threats.yaml"
    )
    tool_source = (
        Path(args.tool_source).expanduser().resolve()
        if args.tool_source
        else plugin_root / "hooks/config/tool-rules.yaml"
    )
    indirect_source = (
        Path(args.indirect_source).expanduser().resolve()
        if args.indirect_source
        else plugin_root / "hooks/config/indirect-injection-patterns.yaml"
    )
    override_source = (
        Path(args.override_source).expanduser().resolve()
        if args.override_source
        else Path.home() / ".config/secure-claude/overrides.yaml"
    )
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else Path.home() / ".config/secure-claude/generated"
    )

    shipped_prompt_rules, prompt_defaults = compile_shipped_prompt_rules(
        load_yaml_file(prompt_source, "prompt rules"), "prompt rules"
    )
    shipped_tool_rules, tool_defaults = compile_shipped_tool_rules(
        load_yaml_file(tool_source, "tool rules"), "tool rules"
    )

    # Collect shipped indirect injection rule IDs for override protection
    shipped_indirect_ids: set[str] = set()
    indirect_defaults: dict[str, Any] = {}
    if indirect_source.exists():
        shipped_indirect_rules, indirect_defaults = compile_shipped_prompt_rules(
            load_yaml_file(indirect_source, "indirect injection rules"),
            "indirect injection rules",
        )
        shipped_indirect_ids = {rule["id"] for rule in shipped_indirect_rules}

    prompt_output = output_dir / "user-prompt-threats.json"
    tool_output = output_dir / "tool-rules.json"
    indirect_output = output_dir / "indirect-injection-patterns.json"

    if not override_source.exists():
        remove_if_present(prompt_output)
        remove_if_present(tool_output)
        remove_if_present(indirect_output)
        return

    override_document = load_yaml_file(override_source, "local overrides")
    ensure_unknown_keys_absent(
        override_document,
        {"promptPatterns", "toolRules", "indirectInjectionRules"},
        "local overrides",
    )

    prompt_rules = compile_prompt_overrides(
        override_document,
        prompt_defaults,
        {rule["id"] for rule in shipped_prompt_rules},
        "local overrides",
    )
    tool_rules = compile_tool_overrides(
        override_document,
        tool_defaults,
        {rule["id"] for rule in shipped_tool_rules},
        "local overrides",
    )

    # Compile local indirect injection overrides
    indirect_rules_list = ensure_list(
        override_document.get("indirectInjectionRules"),
        "local overrides.indirectInjectionRules",
    )
    indirect_rules: list[dict[str, Any]] = []
    indirect_defaults_local = indirect_defaults if indirect_source.exists() else prompt_defaults
    for index, raw_rule in enumerate(indirect_rules_list):
        rule_label = f"local overrides.indirectInjectionRules[{index}]"
        rule_mapping = ensure_mapping(raw_rule, rule_label)
        merged_rule = {**indirect_defaults_local, **rule_mapping}
        normalized = normalize_prompt_rule(merged_rule, rule_label)
        if normalized["id"] in shipped_indirect_ids:
            raise ConfigError(
                f"{rule_label}: override may not modify shipped rule id: {normalized['id']}"
            )
        indirect_rules.append(normalized)
    validate_unique_ids(indirect_rules, "local overrides.indirectInjectionRules")

    write_or_check_output(prompt_output, render_json(prompt_rules), False, "local prompt overrides")
    write_or_check_output(tool_output, render_json(tool_rules), False, "local tool overrides")
    write_or_check_output(
        indirect_output, render_json(indirect_rules), False, "local indirect injection overrides"
    )


def main() -> int:
    args = parse_args()
    plugin_root = resolve_plugin_root(args)
    try:
        if args.mode == "shipped":
            compile_shipped(args, plugin_root)
        elif args.mode == "overrides":
            compile_local(args, plugin_root)
        else:  # both
            compile_shipped(args, plugin_root)
            compile_local(args, plugin_root)
    except ConfigError as exc:
        print(f"compile_config: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
