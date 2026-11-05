
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
