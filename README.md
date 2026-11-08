
# Purpose

Scripts to harden Windows (11,10).
Assist to remove unnecessary Windows apps, disable telemetry, inactivate bloatware and disable unecessary or insecure default features and enable some security features.
Attempts to improve security and privacy posture.

![alt text](windowsdebloatersponge.png)

## Specificity of this tool

The "difference" of this tool is a focus on granularity (1 script for one 1 control) as all-in-one scripts are rapidly impossible to use or obsolete or difficult to use and maintain.
A current profile (TBC) would be the update of the day sequence of each required specic unique control. Obsolete controls would be moved to a deprecated folder.

## Usage

This tool is mainly focused on a **powershell** approach and add others scripts ( batch, powershell, python, ansible ) for reference. Scripts are in <https://github.com/blue101010/Windows10Debloater/tree/master/security/default> directory.

### Google Chrome update policies

The Windows 11 `0108` PowerShell scripts set individual Google Update policies.
Run the desired scripts as Administrator:

- [`0108.001`](security/default/0108.001_Enable_Google_updates_default.ps1)
  allows automatic and manual updates by default for Google applications.
- [`0108.002`](security/default/0108.002_Set_Google_update_check_period.ps1)
  sets the minimum interval between automatic checks to 20 minutes for Google applications.
- [`0108.003`](security/default/0108.003_Enable_Chrome_updates.ps1)
  allows automatic and manual Chrome updates, overriding the default for Chrome.
- [`0108.004`](security/default/0108.004_Enable_Google_automatic_update_checks.ps1)
  preserves a legacy update-check setting; its effect on current Google Updater
  versions has not been established.

These scripts write the 64-bit machine policy key; they do not enable updater
services or scheduled tasks, install Chrome, or remove other conflicting policies.
Google documents that computer Group Policy settings require domain-joined or
MDM-managed devices. Check `chrome://policy` and the updater status to confirm
the effective configuration. See [Google's update management documentation](https://support.google.com/chrome/a/answer/6350036).

The `0109` Chrome script disables a security feature and should only be used
when necessary. The `0113` online speech script targets the current user.
Scripts `0123` through `0125` disable their listed scheduled tasks and report
tasks that are absent. [`0126`](security/default/0126_Disable_Microsoft_Windows_SettingSync.ps1)
disables registered SettingSync tasks instead of deleting task files, unlike the
old batch file. Disabling Family Safety or SettingSync tasks can affect those
features. Run machine-wide registry and scheduled-task scripts as Administrator.

### CIS registry import review

The review of [`0131_hklm-cis-windows.reg`](security/default/0131_hklm-cis-windows.reg)
is **incomplete**. Edge Legacy controls and single-value blocks matching the
same DWORD key, name, and data in the
[`0205` DSC configuration](security/default/0205_Configure_CIS_Windows10_V181_DSC_hardening.ps1)
have been removed, as have five settings implemented by
[`0342`](security/default/0342_windows-11-hardening-script.bat).
The DSC configuration is a definition, not an automatically applied replacement.
Other duplicate and obsolete controls may remain; the remaining entries are not
certified for Windows 11. Removing entries does not undo prior imports. Review
the file and its security impact before importing it.

### Remaining controls in all.bat

[`security/default/all.bat`](security/default/all.bat) retains 81 active
registry writes and nine commented optional writes after removing equivalents
found in other repository scripts, registry-import files, PowerShell functions,
and DSC configurations (including deprecated files). Equivalence requires the
same hive, key, value name, registry type, and data; comments and read-only
checks are not replacements. Entries with different data or registry locations
remain unchanged.

The Windows 11 cleanup additionally removes 34 registry writes and six
firewall commands targeting obsolete or retired features:

| Removed controls | Reason |
| --- | --- |
| Active Desktop and desktop Sidebar gadgets | Active Desktop policies target pre-Vista Windows; gadgets were removed in Windows 8. |
| `HidePeopleBar` | My People is not present on the Windows 11 taskbar. |
| NetMeeting `NoRDS` | Controls NetMeeting desktop sharing, not modern Remote Desktop. |
| `PCHealth\ErrorReporting` and `PCHealth\HelpSvc` | XP-era error reporting and Help and Support Center settings. Modern Windows Error Reporting controls remain. |
| Two DeviceInstall-to-WER settings | Their ADMX supported-version ranges end at Windows 10 version 1709. |
| `NoInternetOpenWith` and GameUX settings | Legacy Open With web lookup (ADMX range ends at Windows 7) and removed Games Explorer. |
| UE-V Windows8AppList synchronization | The UE-V client is deprecated; extended support ended April 14, 2026. |
| Offline Maps download settings | Maps is deprecated and no longer supported. |
| `DisableAntiSpyware` | Microsoft removed this legacy Defender configuration setting. Other Defender settings remain. |
| Cortana and OneNote UWP firewall groups/program rules | Cortana is deprecated; OneNote for Windows 10 reached end of support in October 2025. |

Sources: [Windows 11 feature deprecations](https://www.microsoft.com/en-us/windows/windows-11-specifications),
[deprecated Windows features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features),
[desktop gadgets removal](https://learn.microsoft.com/en-us/windows/compatibility/desktop-gadgets-removed),
[diagnostic data settings](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization),
[DisableAntiSpyware](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware),
and [OneNote UWP migration](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/onenote-for-windows-10-migration-guide).
Legacy policy applicability was also checked against Windows 11 ADMX definitions.

This batch file is no longer a complete hardening baseline and does not invoke
replacement scripts. Removing commands does not undo settings applied by earlier
runs. Firewall-rule deletions for retired apps remain to clean up earlier runs.
Optional features such as Wireless Display and legacy Windows Media Player are
not treated as removed merely because they are not installed. Scheduled-task
commands are unchanged; availability can vary by build and installed software.
Review the remaining controls before running it as Administrator.

Run the static checks without modifying Windows settings:

```powershell
powershell -NoProfile -File .\tests\all.Windows11.Tests.ps1
```

### Windows 11 script applicability audit (24H2-26H2)

39 wholly legacy or retired scripts were moved, without changing their contents,
from [`security/default`](security/default) to
[`security/deprecated`](security/deprecated). This includes older-than-Windows-10
controls as well as Windows 10-only controls and features removed in Windows 11.
Archiving does not undo previously applied settings.

| Archived script IDs | Count | Technical reason |
| --- | --- | --- |
| `0036.01`, `0411` | 2 | Only `AllowCortana` / `AllowCortanaAboveLock`; the standalone Cortana app is retired. |
| `0036.02` | 1 | `DisableWebSearch` is the legacy Windows Desktop Search policy: Search.admx resolves `RedistOnly` to XP/Server 2003 with Windows Search 3.01+. It is not a supported Windows 11 web-search control. |
| `0088_001` through `0088_017`, `0162`, `0163`, `0216` | 20 | Only legacy `DeviceAccess` writes, with no CapabilityAccessManager or AppPrivacy implementation. The 0088 scripts themselves identify the pre-1903 limitation; successful readback of this old key does not prove enforcement. `0088_017` also explicitly describes its writes as reference/TODO, not working permission removal. |
| `0077` | 1 | Only MapsBroker and Maps scheduled tasks; Windows Maps is no longer supported. |
| `0171` | 1 | Comment-only Holographic/FirstRunSucceeded reference; Mixed Reality Portal was removed in 24H2. |
| `0225` | 1 | Enables `Windows-Defender-ApplicationGuard`, removed in 24H2. |
| `0168`, `0294`, `0298` | 3 | Only legacy EdgeHTML `MicrosoftEdge`/AppContainer settings, not Chromium `Microsoft\Edge` policies. |
| `0295`, `0296`, `0297` | 3 | EdgeUI policies for the Windows 8/8.1 corner-based app switcher/PC settings UI, not the Edge browser or Windows 11 Task View. |
| `0312` through `0315` | 4 | Only EMET SysSettings; EMET support ended in 2018. Use modern Exploit Protection instead. |
| `0179` | 1 | Hard-coded Windows 10 build 10240 CBS package identities; not Windows 11 package removal. |
| `0180` | 1 | Only `UploadUserActivities`; Timeline cloud synchronization ended for Microsoft accounts in 2021 and Entra accounts in January 2024. |
| `0327` | 1 | Only `wmic qfe`; Microsoft lists WMIC as removed from 24H2 and above. WMI/CIM itself is not removed. |

Method: inspect executed commands rather than filenames, resolve local
ADMX/ADML `supportedOn` identifiers (including upper limits), and cross-check
[Policy CSP applicability](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider),
[removed features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features),
[deprecated features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features),
[Edge Legacy retirement](https://support.microsoft.com/en-gb/edge/what-is-microsoft-edge-legacy),
and [EMET lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/enhanced-mitigation-experience-toolkit-emet).
An ADMX entry's presence, a Windows 10 minimum version, or a feature missing on
one computer is not sufficient proof of Windows 11 obsolescence. The DeviceAccess
classification additionally relies on the existing scripts' documented legacy
scope, rather than claiming a Microsoft ADMX removal notice for those raw keys.

Mixed scripts stay in default, including the Cortana aggregate, the large CIS/DSC
collections and Windows 10-named hardening libraries. Their retention does
**not** certify every command inside them. `AllowCloudSearch` and
`AllowSearchToUseLocation` remain because they also govern Windows Search.
Modern AppPrivacy controls remain in
[`0056_Disable_with_policy_apprivacy.ps1`](security/default/0056_Disable_with_policy_apprivacy.ps1).
Steps Recorder, online speech, optional features, and controls with uncertain
removal dates were not archived merely because of a deprecation announcement.
The Windows 11 profile no longer calls the archived standalone controls; their
isolated tests now address the archive.

[`security/default/471.md`](security/default/471.md) lists the prioritized missing
Windows 11 controls with technical identities, values and sources. The 50-entry
backlog includes a comparison with
[Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat/blob/5d88bfe9ef2be5a8a643166a6400eb78a30c46ec/Win11Debloat.ps1),
including its feature definitions, registry specifications and apply functions,
not just its command-line switches. Scope is applicability to Windows 11
24H2-26H2, not exclusively controls first introduced in Windows 11.
This is a review backlog, not a script or a universally safe baseline.
Check edition, hardware, servicing level and documented policy applicability
before implementing any entry.

```powershell
powershell -NoProfile -File .\tests\Windows11ScriptInventory.Tests.ps1
```

### Disabling activity history publishing

[`security/default/0011_Disable_Collect_Activity_History_PublishUserActivities.ps1`](security/default/0011_Disable_Collect_Activity_History_PublishUserActivities.ps1)
requests administrator privileges through **UAC** when run from a non-elevated
session. Approve the prompt to continue in an elevated PowerShell process.
Cancellation, launch errors, and elevated-script failures stop execution with
an error; already-elevated sessions do not prompt. It creates missing policy entries, sets
`PublishUserActivities` to DWORD `0`, and verifies the updated value. Registry
errors stop execution; if access is denied even when elevated, check registry
permissions or organization policy rather than bypassing them.

Run isolated tests without changing the registry or displaying UAC prompts:

```powershell
powershell -NoProfile -File .\tests\0011_Disable_Collect_Activity_History_PublishUserActivities.Tests.ps1
```

### Disabling application telemetry

[`security/default/0017_Disable_Application_Telemetry.ps1`](security/default/0017_Disable_Application_Telemetry.ps1)
creates the missing `AppCompat` policy key and sets `AITEnable` to DWORD `0`,
including when the value was previously unconfigured. It requests UAC elevation
when needed, verifies writes, and stops on registry or elevation errors.
An existing `AITEnable` value of `0` is left unchanged.

Run isolated tests without registry changes or UAC prompts:

```powershell
powershell -NoProfile -File .\tests\0017_Disable_Application_Telemetry.Tests.ps1
```

### Global Git configuration

[`security/default/0002_git_config_global.ps1`](security/default/0002_git_config_global.ps1)
sets the current user's global Git author name and email to the values defined in
the script. Git must be on PATH; administrator privileges are not required.
Each setting is read back and checked, with `[SUCCESS]` or `[FAIL]` status output.
The script exits with code 0 on success or 1 on failure. Changes that succeeded
are not rolled back if another setting fails.

Run the isolated tests (requires Git on PATH) without modifying your real global
Git configuration:

```powershell
powershell -NoProfile -File .\tests\0002_git_config_global.Tests.ps1
```

### Default input method

[`security/default/0470_Set_default_input_method_English_US_International.ps1`](security/default/0470_Set_default_input_method_English_US_International.ps1)
keeps only English (United States) with United States-International
(`0409:00020409`) and sets it as the current user's default input method.
**Canadian Multilingual Standard (CMS), all other keyboard layouts, and other
preferred language entries are removed from this user's list.** This also changes
language preferences used by apps and websites. Administrator rights are not
required; run as the intended user and sign out/back in to refresh cached layouts.
Other users, system keyboard files, and the sign-in screen are not changed.
This is a one-time configuration, not a policy blocking later additions or
changes by synchronization, applications, or organization settings.

Run isolated tests without changing the Windows language list:

```powershell
powershell -NoProfile -File .\tests\0470_Set_default_input_method_English_US_International.Tests.ps1
```

### Blocking mshta with AppLocker

[`security/default/0222_block_mshta.ps1`](security/default/0222_block_mshta.ps1)
merges enforced deny rules for `mshta.exe`, including renamed Microsoft-signed
copies. Run as Administrator on Windows with AppLocker enforcement support:

```powershell
.\security\default\0222_block_mshta.ps1 -WhatIf
.\security\default\0222_block_mshta.ps1
```

Review existing AppLocker policy and take a system backup first. The script
preserves existing rules and refuses to enforce existing audit-only executable
rules. Allow baselines are added only for empty executable/packaged-app collections
to prevent unrelated applications being implicitly blocked. It enables automatic
startup of Application Identity, which can activate other existing collections;
that startup setting cannot be reverted to Manual with `sc.exe`. Failures do not
roll back changes. `[confirmed]` means effective policy evaluation denies installed
mshta binaries and the service is running, not that a live launch was tested.
Renamed unsigned replacements are not covered.

Run isolated tests without installing policy or changing services:

```powershell
powershell -NoProfile -File .\tests\0222_block_mshta.Tests.ps1
```

## Credits

This is using various ideas from various initial sources.
With the time I added plenty of variants, modifications and optimizations of my own.

## License

BSD 2-clause
