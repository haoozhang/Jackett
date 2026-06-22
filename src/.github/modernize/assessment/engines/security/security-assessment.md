# Security Assessment Report

**Generated:** 2026-06-22T10:24:26.0000000Z

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | 11 |
| CVE Vulnerabilities | 4 |
| CWE Vulnerabilities | 7 |
| Total Rules Assessed | 59 |
| Rules Passed | 52 |

### By Severity

| Severity | Count |
|----------|-------|
| mandatory | 4 |
| optional | 3 |
| potential | 4 |

## CVE Findings (Dependency Vulnerabilities)

### CVE-2026-33116: Microsoft Security Advisory CVE-2026-33116 - .NET, .NET Framework, and Visual Studio Denial of Service Vulnerability
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Jackett.Server/Jackett.Server.csproj:45

[CVE-2026-33116](https://github.com/advisories/GHSA-37gx-xxp4-5rgx): Microsoft Security Advisory CVE-2026-33116 - .NET, .NET Framework, and Visual Studio Denial of Service Vulnerability

Severity: HIGH

Affected dependencies:
  - System.Security.Cryptography.Xml:8.0.2 (transitive, pulled by Microsoft.AspNetCore at src/Jackett.Server/Jackett.Server.csproj:45)

Recommended fix:
  - Upgrade System.Security.Cryptography.Xml to 8.0.3 or later

### CVE-2026-26171: Microsoft Security Advisory CVE-2026-26171 - .NET Denial of Service Vulnerability
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Jackett.Server/Jackett.Server.csproj:45

[CVE-2026-26171](https://github.com/advisories/GHSA-w3x6-4m5h-cxqf): Microsoft Security Advisory CVE-2026-26171 - .NET Denial of Service Vulnerability

Severity: HIGH

Affected dependencies:
  - System.Security.Cryptography.Xml:8.0.2 (transitive, pulled by Microsoft.AspNetCore at src/Jackett.Server/Jackett.Server.csproj:45)

Recommended fix:
  - Upgrade System.Security.Cryptography.Xml to 8.0.3 or later

### CVE-2018-8292: .NET Core Information Disclosure
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Jackett.Common/Jackett.Common.csproj:20, src/Jackett.Server/Jackett.Server.csproj:45

[CVE-2018-8292](https://github.com/advisories/GHSA-7jgj-8wvc-jh57): .NET Core Information Disclosure

Severity: HIGH

Affected dependencies:
  - System.Net.Http:4.3.0 (transitive, pulled by Microsoft.AspNetCore.Http at src/Jackett.Common/Jackett.Common.csproj:20)
  - System.Net.Http:4.3.0 (transitive in Jackett.Service, Jackett.Tray, Jackett.Updater, Jackett.Server)

Recommended fix:
  - Upgrade System.Net.Http to 4.3.4 or later

### CVE-2019-0820: Regular Expression Denial of Service in System.Text.RegularExpressions
- **Severity:** mandatory
- **Story Points:** 1
- **Files:** src/Jackett.Common/Jackett.Common.csproj:20, src/Jackett.Server/Jackett.Server.csproj:45

[CVE-2019-0820](https://github.com/advisories/GHSA-cmhx-cq75-c4mj): Regular Expression Denial of Service in System.Text.RegularExpressions

Severity: HIGH

Affected dependencies:
  - System.Text.RegularExpressions:4.3.0 (transitive, pulled by Microsoft.AspNetCore.Http at src/Jackett.Common/Jackett.Common.csproj:20)
  - System.Text.RegularExpressions:4.3.0 (transitive in Jackett.Service, Jackett.Tray, Jackett.Updater, Jackett.Server)

Recommended fix:
  - Upgrade System.Text.RegularExpressions to 4.3.1 or later

## CWE Findings (Code-Level Vulnerabilities)

### CWE-477: Use of Obsolete Function
- **Category:** Code Quality
- **Severity:** optional
- **Story Points:** 1
- **Files:** src/Jackett.Common/Utils/Clients/HttpWebClient.cs

HttpWebClient.cs at lines 20-21 extends a legacy WebClient base class and uses the obsolete HttpWebRequest type (line 39, 42). The file itself contains a TODO comment acknowledging it is a legacy implementation ('This implementation is legacy and it is used only by Mono version — TODO: Merge with HttpWebClient2 or remove when we drop support for Mono 5.x'). System.Net.HttpWebRequest is deprecated in modern .NET in favor of HttpClient.

### CWE-681: Incorrect Conversion between Numeric Types
- **Category:** Code Quality
- **Severity:** potential
- **Story Points:** 3
- **Files:** src/Jackett.Common/Utils/ParseUtil.cs

ParseUtil.cs at lines 155 and 164 performs explicit casts from float to long: '(long)value' and '(long)(kb * 1024f)'. Chained calculations like BytesFromTB -> BytesFromGB -> BytesFromMB -> BytesFromKB multiply float values repeatedly, which can accumulate floating-point precision errors before the final cast to long. For large file sizes the result may be slightly incorrect.

### CWE-567: Unsynchronized Access to Shared Data in a Multithreaded Context
- **Category:** Concurrency & Synchronization
- **Severity:** potential
- **Story Points:** 5
- **Files:** src/Jackett.Common/Utils/StringUtil.cs

StringUtil.cs at line 101 declares a private static field: private static char[] MakeValidFileName_invalids. At line 112, this field is read and lazily initialized without any lock or thread-safe mechanism: ar invalids = MakeValidFileName_invalids ?? (MakeValidFileName_invalids = Path.GetInvalidFileNameChars()). In a multithreaded environment, multiple threads could concurrently read null and assign to the static field without synchronization, constituting unsynchronized access to shared data.

### CWE-321: Use of Hard-coded Cryptographic Key
- **Category:** Credentials & Secrets
- **Severity:** potential
- **Story Points:** 5
- **Files:** src/Jackett.Common/Indexers/Definitions/Wolfmax4K.cs

Wolfmax4K.cs at line 53 declares a hard-coded AES encryption key (private const string TorrentLinkEncryptionKey). This key is used at line 188 as the passphrase for the OpenSSLDecryptAsync method to decrypt torrent download links. Using a hard-coded cryptographic key means it cannot be changed without recompiling and is exposed in source code.

### CWE-778: Insufficient Logging
- **Category:** Credentials & Secrets
- **Severity:** potential
- **Story Points:** 3
- **Files:** src/Jackett.Server/Controllers/ResultsController.cs

ResultsController.cs, in the RequiresApiKey.OnActionExecuting method (lines 33-48), validates the API key but does not log failed authentication attempts. When queryApiKey != validApiKey, the code returns an Unauthorized result without logging, making it impossible to detect brute-force attempts or unauthorized access.

### CWE-798: Use of Hard-coded Credentials
- **Category:** Credentials & Secrets
- **Severity:** optional
- **Story Points:** 5
- **Files:** src/Jackett.Common/Indexers/Definitions/Wolfmax4K.cs

Wolfmax4K.cs at line 53 contains a hard-coded credential string TorrentLinkEncryptionKey used as a cryptographic passphrase for AES decryption of torrent links (line 188). This constitutes hard-coded credentials embedded directly in source code.

### CWE-611: Improper Restriction of XML External Entity Reference
- **Category:** File & Path Security
- **Severity:** optional
- **Story Points:** 5
- **Files:** src/Jackett.Common/Indexers/Definitions/EraiRaws.cs

In EraiRaws.cs at line 212-213, a new XmlDocument() is created and LoadXml() is called without explicitly setting XmlResolver = null. When targeting net471 (.NET Framework), XmlDocument allows DTD processing and external entity resolution by default, which can expose the application to XXE attacks if the external RSS feed content is crafted maliciously.

