"""
Rule management handlers for CheckMK monitoring rules
"""

from typing import Any, Dict, List, Optional, Union

from api.exceptions import CheckMKError
from handlers.base import BaseHandler


def json_to_python_literal(obj: Any) -> str:
    """Convert a JSON-compatible value to a Python literal string.

    Handles the key difference between JSON and CheckMK's Python literal format:
    - JSON arrays [] become Python tuples () (CheckMK convention)
    - Python dicts use single quotes
    - Booleans are True/False not true/false
    - None instead of null
    """
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            items.append(f"'{k}': {json_to_python_literal(v)}")
        return "{" + ", ".join(items) + "}"
    elif isinstance(obj, list):
        if len(obj) == 2:
            # Pattern: ("type_string", (warn, crit)) — very common in CheckMK
            if isinstance(obj[0], str) and isinstance(obj[1], (list, tuple)):
                inner = json_to_python_literal(obj[1])
                return f"('{obj[0]}', {inner})"
            # Pattern: (warn_float, crit_float) — threshold pairs
            if all(isinstance(x, (int, float)) for x in obj):
                return f"({obj[0]}, {obj[1]})"
        # Default: convert to tuple (CheckMK convention)
        elements = [json_to_python_literal(x) for x in obj]
        if len(elements) == 1:
            return f"({elements[0]},)"
        return "(" + ", ".join(elements) + ")"
    elif isinstance(obj, str):
        return f"'{obj}'"
    elif isinstance(obj, bool):
        return "True" if obj else "False"
    elif isinstance(obj, (int, float)):
        return str(obj)
    elif obj is None:
        return "None"
    else:
        return repr(obj)


class RulesHandler(BaseHandler):
    """Handle rule management operations"""

    async def handle(self, tool_name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Handle rule-related tool calls"""

        try:
            if tool_name == "vibemk_get_rulesets":
                return await self._get_rulesets(arguments)
            elif tool_name == "vibemk_get_ruleset":
                return await self._get_ruleset(arguments)
            elif tool_name == "vibemk_create_rule":
                return await self._create_rule(arguments)
            elif tool_name == "vibemk_update_rule":
                return await self._update_rule(arguments)
            elif tool_name == "vibemk_delete_rule":
                return await self._delete_rule(arguments)
            elif tool_name == "vibemk_move_rule":
                return await self._move_rule(arguments)
            elif tool_name == "vibemk_backup_ruleset":
                return await self._backup_ruleset(arguments)
            else:
                return self.error_response("Unknown tool", f"Tool '{tool_name}' is not supported")

        except CheckMKError as e:
            return self._format_api_error(e)
        except Exception as e:
            self.logger.exception(f"Error in {tool_name}")
            return self.error_response("Unexpected Error", str(e))

    def _format_api_error(self, error: CheckMKError) -> List[Dict[str, Any]]:
        """Format CheckMK API errors with full detail from the response body."""
        response_data = getattr(error, "response_data", {}) or {}
        status_code = getattr(error, "status_code", None)

        detail = response_data.get("detail", "")
        fields = response_data.get("fields", {})
        title = response_data.get("title", str(error))

        msg = f"CheckMK API Error ({status_code})" if status_code else "CheckMK API Error"
        parts = [f"**{title}**"]
        if detail:
            parts.append(detail)
        if fields:
            for field, errors in fields.items():
                if isinstance(errors, list):
                    parts.append(f"- `{field}`: {', '.join(str(e) for e in errors)}")
                else:
                    parts.append(f"- `{field}`: {errors}")

        return self.error_response(msg, "\n".join(parts))

    async def _get_rulesets(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get list of available rulesets"""
        search = arguments.get("search", "")

        params = {}
        if search:
            params["search"] = search

        result = self.client.get("domain-types/ruleset/collections/all", params=params)

        if not result.get("success"):
            return self.error_response("Failed to retrieve rulesets")

        rulesets = result["data"].get("value", [])
        if not rulesets:
            return [
                {
                    "type": "text",
                    "text": "📋 **No Rulesets Found**\n\nNo rulesets are available or match the search criteria.",
                }
            ]

        ruleset_list = []
        for ruleset in rulesets[:20]:  # Limit to first 20
            ruleset_name = ruleset.get("id", "Unknown")
            extensions = ruleset.get("extensions", {})
            title = extensions.get("title", ruleset_name)
            help_text = extensions.get("help", "No description")

            ruleset_list.append(f"📋 **{ruleset_name}**\n   Title: {title}\n   Help: {help_text[:100]}...")

        response_text = f"📋 **Available Rulesets** ({len(rulesets)} total):\n\n" + "\n\n".join(ruleset_list)
        if len(rulesets) > 20:
            response_text += f"\n\n... and {len(rulesets) - 20} more rulesets"

        return [{"type": "text", "text": response_text}]

    async def _get_ruleset(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get specific ruleset configuration and rules"""
        ruleset_name = arguments.get("ruleset_name")

        if not ruleset_name:
            return self.error_response("Missing parameter", "ruleset_name is required")

        # Use the correct endpoint to get actual rules with ruleset_name parameter
        params = {"ruleset_name": ruleset_name}
        result = self.client.get("domain-types/rule/collections/all", params=params)

        if not result.get("success"):
            return self.error_response("Ruleset not found", f"Ruleset '{ruleset_name}' does not exist or has no rules")

        rules = result["data"].get("value", [])

        rule_list = []
        for i, rule in enumerate(rules[:10]):  # Show first 10 rules
            rule_id = rule.get("id", f"Rule {i+1}")
            extensions = rule.get("extensions", {})
            properties = extensions.get("properties", {})
            comment = properties.get("comment", "No comment")
            disabled = properties.get("disabled", False)
            value_raw = extensions.get("value_raw", "No value")
            folder = extensions.get("folder", "/")
            conditions = extensions.get("conditions", {})

            status = "🔒 Disabled" if disabled else "✅ Active"

            # Format conditions summary
            condition_summary = []
            if conditions.get("host_name"):
                host_match = conditions["host_name"]
                condition_summary.append(
                    f"Hosts: {host_match.get('match_on', [])} ({host_match.get('operator', 'unknown')})"
                )
            if conditions.get("host_tags") and len(conditions["host_tags"]) > 0:
                tag_count = len(conditions["host_tags"])
                condition_summary.append(f"Tags: {tag_count} conditions")
            if conditions.get("host_label_groups") and len(conditions["host_label_groups"]) > 0:
                label_count = len(conditions["host_label_groups"])
                condition_summary.append(f"Labels: {label_count} conditions")

            conditions_text = ", ".join(condition_summary) if condition_summary else "All hosts"

            rule_list.append(
                f"🔧 **Rule {i+1}** (ID: {rule_id})\n"
                f"   Status: {status}\n"
                f"   Value: {value_raw}\n"
                f"   Folder: {folder}\n"
                f"   Conditions: {conditions_text}\n"
                f"   Comment: {comment}"
            )

        return [
            {
                "type": "text",
                "text": (
                    f"📋 **Ruleset: {ruleset_name}**\n\n"
                    f"Rules ({len(rules)} total):\n\n"
                    + ("\n\n".join(rule_list) if rule_list else "No rules configured in this ruleset")
                    + (f"\n\n... and {len(rules) - 10} more rules" if len(rules) > 10 else "")
                ),
            }
        ]

    def _convert_to_value_raw(self, rule_config: Any) -> str:
        """Convert a JSON value to a Python literal string for value_raw.

        Handles simple types directly and uses json_to_python_literal for
        complex dicts/lists that may contain CheckMK tuple patterns.
        """
        if isinstance(rule_config, bool):
            return "True" if rule_config else "False"
        elif isinstance(rule_config, (int, float)):
            return str(rule_config)
        elif isinstance(rule_config, str):
            # Check if it's already a Python literal (starts with dict/tuple/list syntax)
            stripped = rule_config.strip()
            if stripped.startswith(("{", "(", "[", "True", "False", "None")):
                return rule_config
            # Simple string values get quoted
            return f"'{rule_config}'"
        elif isinstance(rule_config, dict):
            return json_to_python_literal(rule_config)
        elif isinstance(rule_config, list):
            return json_to_python_literal(rule_config)
        else:
            return str(rule_config)

    async def _create_rule(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create a new monitoring rule"""
        ruleset_name = arguments.get("ruleset_name")
        rule_config = arguments.get("rule_config")
        value_raw_param = arguments.get("value_raw")
        conditions = arguments.get("conditions", {})
        comment = arguments.get("comment", "")
        folder = arguments.get("folder", "/")
        position = arguments.get("position", "top")

        if not ruleset_name:
            return self.error_response("Missing parameter", "ruleset_name is required")

        if not value_raw_param and rule_config is None:
            return self.error_response(
                "Missing parameter",
                "Either `value_raw` or `rule_config` is required.\n\n"
                "Use `value_raw` for complex Python-literal values (checkgroup_parameters, etc.).\n"
                "Use `rule_config` for simple values (strings, numbers, simple dicts).",
            )

        # Build rule data structure according to CheckMK 2.3 OpenAPI specification
        # Convert folder path: "/" -> "~", "/hosts/linux" -> "~hosts~linux"
        if folder.startswith("/"):
            api_folder = "~" + folder[1:].replace("/", "~") if folder != "/" else "~"
        else:
            api_folder = "~" + folder.replace("/", "~")

        # Determine value_raw: direct passthrough takes priority
        if value_raw_param:
            value_raw = value_raw_param
        else:
            value_raw = self._convert_to_value_raw(rule_config)

        data = {
            "properties": {"disabled": False},
            "value_raw": value_raw,
            "conditions": conditions if conditions else {},
            "ruleset": ruleset_name,
            "folder": api_folder,
        }

        # Add comment to properties if provided
        if comment:
            data["properties"]["comment"] = comment

        result = self.client.post("domain-types/rule/collections/all", data=data)

        if result.get("success"):
            rule_id = result["data"].get("id", "unknown")
            return [
                {
                    "type": "text",
                    "text": (
                        f"✅ **Rule Created Successfully**\n\n"
                        f"Ruleset: {ruleset_name}\n"
                        f"Rule ID: {rule_id}\n"
                        f"Folder: {folder}\n"
                        f"Value (raw): `{value_raw}`\n"
                        f"Comment: {comment}\n\n"
                        f"⚠️ **Remember to activate changes!**"
                    ),
                }
            ]
        else:
            return self.error_response("Rule creation failed", f"Could not create rule in ruleset '{ruleset_name}'")

    async def _update_rule(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Update an existing rule"""
        rule_id = arguments.get("rule_id")
        rule_config = arguments.get("rule_config")
        value_raw_param = arguments.get("value_raw")
        conditions = arguments.get("conditions")
        comment = arguments.get("comment")
        disabled = arguments.get("disabled")

        if not rule_id:
            return self.error_response("Missing parameter", "rule_id is required")

        # Build update data
        data = {}

        # value_raw takes priority over rule_config
        if value_raw_param:
            data["value_raw"] = value_raw_param
        elif rule_config is not None:
            data["value_raw"] = self._convert_to_value_raw(rule_config)

        if conditions:
            data["conditions"] = conditions

        properties = {}
        if comment is not None:
            properties["comment"] = comment
        if disabled is not None:
            properties["disabled"] = disabled
        if properties:
            data["properties"] = properties

        if not data:
            return self.error_response("No data to update", "At least one field must be provided")

        # Use ETag for optimistic locking
        headers = {"If-Match": "*"}
        result = self.client.put(f"objects/rule/{rule_id}", data=data, headers=headers)

        if result.get("success"):
            return [
                {
                    "type": "text",
                    "text": (
                        f"✅ **Rule Updated Successfully**\n\n"
                        f"Rule ID: {rule_id}\n"
                        f"Updated fields: {', '.join(data.keys())}\n\n"
                        f"⚠️ **Remember to activate changes!**"
                    ),
                }
            ]
        else:
            return self.error_response("Rule update failed", f"Could not update rule '{rule_id}'")

    async def _backup_ruleset(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Backup all rules from a ruleset, returning full JSON including value_raw."""
        ruleset_name = arguments.get("ruleset_name")

        if not ruleset_name:
            return self.error_response("Missing parameter", "ruleset_name is required")

        params = {"ruleset_name": ruleset_name}
        result = self.client.get("domain-types/rule/collections/all", params=params)

        if not result.get("success"):
            return self.error_response(
                "Backup failed", f"Could not retrieve rules for ruleset '{ruleset_name}'"
            )

        rules = result["data"].get("value", [])

        if not rules:
            return [
                {
                    "type": "text",
                    "text": f"📋 **Ruleset Backup: {ruleset_name}**\n\nNo rules found in this ruleset.",
                }
            ]

        import json

        backup_entries = []
        for rule in rules:
            rule_id = rule.get("id", "unknown")
            extensions = rule.get("extensions", {})
            backup_entries.append(
                {
                    "rule_id": rule_id,
                    "value_raw": extensions.get("value_raw"),
                    "conditions": extensions.get("conditions", {}),
                    "properties": extensions.get("properties", {}),
                    "folder": extensions.get("folder", "/"),
                    "ruleset": extensions.get("ruleset", ruleset_name),
                }
            )

        backup_json = json.dumps(backup_entries, indent=2)

        return [
            {
                "type": "text",
                "text": (
                    f"📋 **Ruleset Backup: {ruleset_name}**\n\n"
                    f"Rules: {len(rules)}\n\n"
                    f"```json\n{backup_json}\n```"
                ),
            }
        ]

    async def _delete_rule(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Delete a rule"""
        rule_id = arguments.get("rule_id")

        if not rule_id:
            return self.error_response("Missing parameter", "rule_id is required")

        result = self.client.delete(f"objects/rule/{rule_id}")

        if result.get("success"):
            return [
                {
                    "type": "text",
                    "text": (
                        f"✅ **Rule Deleted Successfully**\n\n"
                        f"Rule ID: {rule_id}\n\n"
                        f"📝 **Next Steps:**\n"
                        f"1️⃣ Use 'get_pending_changes' to review the deletion\n"
                        f"2️⃣ Use 'activate_changes' to apply the configuration\n\n"
                        f"💡 **Important:** The rule is only marked for deletion until you activate changes!"
                    ),
                }
            ]
        else:
            return self.error_response("Rule deletion failed", f"Could not delete rule '{rule_id}'")

    async def _move_rule(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Move a rule to different position"""
        rule_id = arguments.get("rule_id")
        position = arguments.get("position", "top")  # top, bottom, before, after
        target_rule_id = arguments.get("target_rule_id")  # for before/after

        if not rule_id:
            return self.error_response("Missing parameter", "rule_id is required")

        if position in ["before", "after"] and not target_rule_id:
            return self.error_response("Missing parameter", "target_rule_id is required for before/after positioning")

        # Build move data
        data = {"position": position}
        if target_rule_id:
            data["target_rule"] = target_rule_id

        result = self.client.post(f"objects/rule/{rule_id}/actions/move/invoke", data=data)

        if result.get("success"):
            return [
                {
                    "type": "text",
                    "text": (
                        f"✅ **Rule Moved Successfully**\n\n"
                        f"Rule ID: {rule_id}\n"
                        f"New Position: {position}\n"
                        + (f"Target Rule: {target_rule_id}\n" if target_rule_id else "")
                        + f"\n⚠️ **Remember to activate changes!**"
                    ),
                }
            ]
        else:
            return self.error_response("Rule move failed", f"Could not move rule '{rule_id}'")
