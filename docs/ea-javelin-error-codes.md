# EA Javelin Error Codes

Collected from public player reports and EA support documentation.

| Code | Reported Message            | Likely Cause                    |
|------|-----------------------------|--------------------------------|
| 5    | "AntiCheat Error 5:701"     | Service failed to start         |
| 7    | "Error (7) (2)"             | Service launch failure          |
| 87   | "Error 87"                  | `ERROR_INVALID_PARAMETER`       |
| 94   | "Error 94"                  | Anti-cheat update failure       |
| 95   | Event Viewer exit 95        | Blacklisted software detected   |
| 119  | "Incompatible driver"       | Unsigned/conflicting driver     |

## Launch Checks

EA Javelin validates the following at game launch:
- Secure Boot status
- TPM 2.0 presence
- Driver signatures
- Conflicting software (overlays, debuggers)
