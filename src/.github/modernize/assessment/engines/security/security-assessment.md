# Security Assessment Report

**Generated:** 06/22/2026 07:27:32

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | 8 |
| CVE Vulnerabilities | 4 |
| CWE Vulnerabilities | 4 |
| Total Rules Assessed | 59 |
| Rules Passed | 55 |

### By Severity

| Severity | Count |
|----------|-------|
| mandatory | 4 |
| optional | 1 |
| potential | 3 |

## CVE Findings (Dependency Vulnerabilities)
### CVE-2026-33116: Microsoft Security Advisory CVE-2026-33116 - .NET, .NET Framework, and Visual Studio Denial of Service Vulnerability
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** Jackett.Server/Jackett.Server.csproj

[CVE-2026-33116](https://github.com/advisories/GHSA-9p97-h2g6-4jm5): Microsoft Security Advisory CVE-2026-33116 - .NET, .NET Framework, and Visual Studio Denial of Service Vulnerability

Severity: HIGH

Affected dependencies:
  - System.Security.Cryptography.Xml:8.0.2 (transitive, included in Jackett.Server/Jackett.Server.csproj)

Recommended fix:
  - Upgrade System.Security.Cryptography.Xml to 8.0.3 or later
### CVE-2026-26171: Microsoft Security Advisory CVE-2026-26171 - .NET Denial of Service Vulnerability
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** Jackett.Server/Jackett.Server.csproj

[CVE-2026-26171](https://github.com/advisories/GHSA-x96m-3w42-r7gc): Microsoft Security Advisory CVE-2026-26171 - .NET Denial of Service Vulnerability

Severity: HIGH

Affected dependencies:
  - System.Security.Cryptography.Xml:8.0.2 (transitive, included in Jackett.Server/Jackett.Server.csproj)

Recommended fix:
  - Upgrade System.Security.Cryptography.Xml to 8.0.3 or later
### CVE-2018-8292: .NET Core Information Disclosure
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** Jackett.Common/Jackett.Common.csproj, Jackett.Server/Jackett.Server.csproj, Jackett.Service/Jackett.Service.csproj, Jackett.Tray/Jackett.Tray.csproj, Jackett.Updater/Jackett.Updater.csproj

[CVE-2018-8292](https://github.com/advisories/GHSA-7jgj-8wvc-jh57): .NET Core Information Disclosure

Severity: HIGH

Affected dependencies:
  - System.Net.Http:4.3.0 (transitive, included in multiple projects)

Recommended fix:
  - Upgrade System.Net.Http to 4.3.4 or later
### CVE-2019-0820: Regular Expression Denial of Service in System.Text.RegularExpressions
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** Jackett.Common/Jackett.Common.csproj, Jackett.Server/Jackett.Server.csproj, Jackett.Service/Jackett.Service.csproj, Jackett.Tray/Jackett.Tray.csproj, Jackett.Updater/Jackett.Updater.csproj

[CVE-2019-0820](https://github.com/advisories/GHSA-cmhx-cq75-c4mj): Regular Expression Denial of Service in System.Text.RegularExpressions

Severity: HIGH

Affected dependencies:
  - System.Text.RegularExpressions:4.3.0 (transitive, included in multiple projects)

Recommended fix:
  - Upgrade System.Text.RegularExpressions to 4.3.1 or later
## CWE Findings (Code-Level Vulnerabilities)
### CWE-772: Missing Release of Resource after Effective Lifetime
- **Category:** Code Quality
- **Severity:** potential
- **Story Points:** 3
- **Files:** Jackett.Common/Services/UpdateService.cs

In UpdateService.ExtractUpdate() (lines 289-296), Stream objects 'inStream' and 'gzipStream' are opened without using 'using' blocks. If tarArchive.ExtractContents() or subsequent operations throw an exception, these streams will not be closed/disposed, resulting in a resource leak.
### CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
- **Category:** Code Quality
- **Severity:** potential
- **Story Points:** 3
- **Files:** Jackett.Common/Services/UpdateService.cs

In UpdateService.ExtractUpdate() (lines 289-296), File.OpenRead() returns a stream that is closed with explicit .Close() calls rather than using 'using' blocks. If an exception occurs during extraction, the file handles for 'inStream' and 'gzipStream' will not be released.
### CWE-321: Use of Hard-coded Cryptographic Key
- **Category:** Credentials & Secrets
- **Severity:** potential
- **Story Points:** 5
- **Files:** Jackett.Server/Services/ProtectionService.cs

In ProtectionService.cs (line 10), a hard-coded cryptographic key 'ApplicationKey' is defined as a constant string. This key is used as the default protection purpose for ASP.NET Core Data Protection when the JACKETT_KEY environment variable is not set (line 18). Any deployment that does not set JACKETT_KEY will use this shared, publicly-known key to protect sensitive data such as indexer credentials.
### CWE-732: Incorrect Permission Assignment for Critical Resource
- **Category:** Credentials & Secrets
- **Severity:** optional
- **Story Points:** 5
- **Files:** Jackett.Common/Services/ConfigurationService.cs

In ConfigurationService.cs (lines 58-60, 132-133, 144-145), the application's data directory and migrated configuration files are assigned FileSystemRights.FullControl for WellKnownSidType.WorldSid (Everyone), granting all local users full read/write access to the Jackett configuration directory which contains API keys and indexer credentials.

