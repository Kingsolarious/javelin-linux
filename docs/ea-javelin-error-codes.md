# EA Javelin error codes (from public sources)

collated from EA forums, support articles, and player reports.
not official EA documentation.

## known error codes

| code | what players report | likely cause |
|---|---|---|
| 5 | "anticheat error 5:701" | javelin service failed to start. corrupt install or conflicting software. |
| 7 | "error (7) (2)" | service launch failure. often after javelin updates brick installs. |
| 87 | "error 87" | launch failure. generic windows error (ERROR_INVALID_PARAMETER). |
| 94 | "error 94" | javelin update broke multiple titles. EA pushed a bad update. |
| 95 | "exit type 95 (207)" | blacklisted software detected (e.g. system informer running). |
| 119 | "error 119" | incompatible driver detected. update or disable the flagged driver. |

## files involved

from crash dumps and process monitors:
- `C:\Program Files\EA\AC\EAAntiCheat.GameService.exe` — usermode service
- `C:\Program Files\EA\AC\EAAntiCheat.GameServiceLauncher.exe` — launcher
- `C:\Program Files\EA\AC\EAAntiCheat.GameServiceLauncher.dll` — launcher DLL
- `C:\Program Files\EA\AC\EAAntiCheat.Installer.exe` — installer/repair tool
- `C:\Windows\System32\drivers\EAAntiCheat.sys` — kernel driver (minifilter, altitude 363250)

## what javelin checks at launch

from player reports and EA support docs:
- Secure Boot enabled
- TPM 2.0 present (on some titles)
- no unsigned/incompatible drivers loaded
- no known "cheat" tools or debuggers running
- no overlays that hook into the game (some frame interpolators, crosshair apps)
- game files not modified

## what this tells us

javelin follows the standard kernel anti-cheat pattern:
1. usermode launcher/service starts first
2. loads kernel driver `EAAntiCheat.sys`
3. driver registers callbacks (process/thread creation, image load, minifilter)
4. usermode DLL injected into game process
5. communicates with backend via the service

the error codes mostly relate to step 1 and 2 failing. this suggests
javelin's usermode component does environment checks before even
loading the driver.

## sources

- EA Forums: BF2042 technical issues board (multiple threads, 2024-2026)
- EA Forums: BF6 technical issues board
- NoPing.com: "Guide to Fix Battlefield 6 AntiCheat Error" (nov 2025)
- GitHub: winsiderss/systeminformer issue #2647 (aug 2025) — documents
  error 95 / exit type 95 when System Informer is running
- EA Answers HQ: "EA AntiCheat Crash Report Handler Error" (feb 2024)
