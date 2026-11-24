"""
Field-name mapping from common Sigma field names to plausible Wazuh/decoded
Windows-eventlog field names.

IMPORTANT: these mappings are approximate defaults based on common Wazuh
Windows eventchannel decoding (win.eventdata.*). The exact field name
available in a real Wazuh deployment depends on the active decoder/ruleset
version. Always validate generated rules against real log samples
(e.g. with `wazuh-logtest`) before deploying to production.
"""

from __future__ import annotations

# Sigma field name (as commonly seen in process_creation / Sysmon-style rules)
# -> Wazuh field name used inside <field name="..."> or <data>/<extra_data> matches.
DEFAULT_FIELD_MAP: dict[str, str] = {
    "Image": "win.eventdata.image",
    "OriginalFileName": "win.eventdata.originalFileName",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "User": "win.eventdata.user",
    "TargetFilename": "win.eventdata.targetFilename",
    "TargetObject": "win.eventdata.targetObject",
    "DestinationIp": "win.eventdata.destinationIp",
    "DestinationPort": "win.eventdata.destinationPort",
    "SourceIp": "win.eventdata.sourceIp",
    "EventID": "win.system.eventID",
    "LogonType": "win.eventdata.logonType",
    "IpAddress": "win.eventdata.ipAddress",
    "ServiceName": "win.eventdata.serviceName",
    "ServiceFileName": "win.eventdata.serviceFileName",
}


def map_field(sigma_field: str) -> str:
    """Return the Wazuh field name for a given Sigma field name.

    Falls back to a lowercase win.eventdata.<field> guess when the field
    is not in the known map, and marks it so the caller can warn the user.
    """
    if sigma_field in DEFAULT_FIELD_MAP:
        return DEFAULT_FIELD_MAP[sigma_field]
    # Unknown field: best-effort guess, caller should flag this as unverified.
    return f"win.eventdata.{sigma_field[0].lower()}{sigma_field[1:]}"


def is_known_field(sigma_field: str) -> bool:
    return sigma_field in DEFAULT_FIELD_MAP
