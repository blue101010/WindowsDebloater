
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
