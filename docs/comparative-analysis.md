# Comparative Analysis

## Correction

Earlier versions of this document incorrectly stated that Easy Anti-Cheat and BattlEye use kernel modules on Linux. They do not. Both run in userspace on Linux.

Battlefield does not use EAC or BattlEye. It uses EA's proprietary kernel-level anti-cheat, **EA Javelin Anticheat**, which is unrelated to this project.

## Architecture Comparison

|                        | Windows         | Linux                  |
|------------------------|-----------------|------------------------|
| EA Javelin Anticheat   | Kernel driver   | Does not exist         |
| Easy Anti-Cheat        | Kernel driver   | Userspace              |
| BattlEye               | Kernel driver   | Userspace              |
| **javelin-linux**      | N/A             | eBPF LSM hooks         |

## Limitations

This project is unaffiliated with Electronic Arts. EA Javelin's actual API is undocumented and proprietary. The shim is based on generic Windows NT patterns and common anti-cheat behaviors. It is not known whether this matches EA Javelin's real API.

Production deployment would require cooperation from the game publisher (signed certificate, backend infrastructure).
