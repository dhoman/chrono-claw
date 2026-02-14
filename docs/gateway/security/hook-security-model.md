---
summary: "Security model for hooks: supply-chain hardening, threat model, defense layers"
read_when:
  - You want to understand the security posture of hooks and plugins
  - You are auditing installed hooks or plugins
  - You want to harden a deployment against supply-chain attacks
title: "Hook Security Model"
---

# Hook Security Model

Hooks are an extensible event-driven system that runs third-party code inside the gateway process. This makes them a supply-chain attack surface. This document describes the threat model, defense layers, and auditing procedures.

## Overview

Hooks execute arbitrary TypeScript/JavaScript when agent events fire. Because they run inside the gateway process (not in a sandbox), the security model focuses on **preventing malicious code from entering the system** rather than containing it at runtime.

Defense is layered: npm install hardening prevents malicious packages from running lifecycle scripts, archive extraction rejects path traversal and zip bombs, module loading restricts imports to workspace-relative paths, and a static scanner catches dangerous patterns before CI merges.

## Threat Model

| Threat                    | Vector                                                         | Impact   |
| ------------------------- | -------------------------------------------------------------- | -------- |
| Malicious npm package     | Lifecycle scripts (`postinstall`) run arbitrary shell commands | Critical |
| Zip bomb                  | Archive with extreme compression ratio exhausts memory/disk    | High     |
| Path traversal (zip slip) | Archive entries escape extraction directory                    | Critical |
| Symlink attack            | Tar symlinks point outside extraction directory                | Critical |
| Module loading escape     | Handler imports load code outside workspace                    | Critical |
| Environment harvesting    | Hook reads `process.env` and exfiltrates secrets via network   | Critical |
| Dynamic code execution    | `eval()` / `new Function()` bypass static analysis             | High     |
| Obfuscated payloads       | Hex/base64 encoded strings hide malicious intent               | Medium   |
| Dependency confusion      | Typosquatted package name resolves to attacker-controlled pkg  | High     |
| Crypto mining             | Hook silently mines cryptocurrency using host resources        | Medium   |

## Defense Layers

### 1. npm Install Hardening

When hooks are installed via `openclaw hooks install`, dependencies are fetched with:

- **`--ignore-scripts`**: No lifecycle scripts (`preinstall`, `postinstall`, etc.) are executed. This blocks the most common supply-chain attack vector.
- **`--omit=dev`**: Only production dependencies are installed, reducing attack surface.
- **Registry-only specs**: Only `<name>` and `<name>@<version>` formats are accepted. Git URLs, file paths, and arbitrary URLs are rejected.

### 2. Archive Extraction Protection

Archive extraction (for hook packs distributed as `.zip` or `.tgz`) enforces:

| Limit               | Default | Purpose                          |
| ------------------- | ------- | -------------------------------- |
| `maxArchiveBytes`   | 256 MB  | Prevents decompression bombs     |
| `maxEntries`        | 50,000  | Prevents entry-count exhaustion  |
| `maxExtractedBytes` | 512 MB  | Caps total extracted size        |
| `maxEntryBytes`     | 256 MB  | Caps single-entry extracted size |

Additional path validation:

- **Traversal detection**: Entries with `..` segments are rejected.
- **Backslash normalization**: `\` is treated as `/` to prevent Windows-style traversal.
- **Absolute path rejection**: Entries starting with `/` or a Windows drive letter (`C:\`) are blocked.
- **Symlink rejection**: Tar entries of type `SymbolicLink`, `Link`, `BlockDevice`, `CharacterDevice`, `FIFO`, or `Socket` are rejected.

### 3. Module Loading Restrictions

Hook handler modules must pass the `isSafeRelativeModulePath` check:

- Must be non-empty after trimming whitespace.
- Must not be an absolute path.
- Must not start with `~` (home directory expansion).
- Must not contain `:` (blocks URL-like and Windows drive-letter paths).
- Must not contain `..` path segments (blocks directory traversal).

At runtime, the hook loader additionally verifies that the resolved module path stays within the workspace directory using `path.relative()` containment checks.

### 4. Skill Scanner (Static Analysis)

The skill scanner (`src/security/skill-scanner.ts`) applies 8 detection rules to source files:

| Rule ID                  | Severity | What It Detects                                   |
| ------------------------ | -------- | ------------------------------------------------- |
| `dangerous-exec`         | critical | `child_process` exec/spawn calls                  |
| `dynamic-code-execution` | critical | `eval()` / `new Function()`                       |
| `crypto-mining`          | critical | Mining pool references (stratum, coinhive, xmrig) |
| `env-harvesting`         | critical | `process.env` access combined with network sends  |
| `suspicious-network`     | warn     | WebSocket to non-standard ports                   |
| `potential-exfiltration` | warn     | File reads combined with network sends            |
| `obfuscated-code`        | warn     | Hex-encoded sequences (6+ consecutive `\xHH`)     |
| `obfuscated-code`        | warn     | Large base64 payloads with decode calls           |

The scanner runs in CI as a required gate (`pnpm scan:skills`). It scans the `skills/` and `extensions/` directories. **Critical findings block the merge**; warnings are annotated but do not block.

### 5. Hook ID Validation

Hook IDs (directory names) are validated during discovery:

- No path separators (`/`, `\`).
- No `.` or `..` components.
- Must be non-empty.

This prevents a malicious hook from masquerading as a directory traversal path.

## Auditing Installed Hooks

### List all hooks

```bash
openclaw hooks list --verbose
```

### Inspect a specific hook

```bash
openclaw hooks info <hook-name>
```

### Deep security audit

```bash
openclaw security audit --deep
```

The deep audit scans installed hook source files with the skill scanner rules and reports any findings.

### Check install records

Install records in the config (`hooks.internal.installs`) track:

- **source**: `npm`, `archive`, or `path`
- **spec**: The original install specifier
- **version**: Installed version
- **installedAt**: ISO timestamp of installation

Review install records to verify that all installed hooks came from expected sources.

## Plugin Version Pinning

Hooks installed from npm use **exact version pinning** by default. The install record stores the exact version that was resolved at install time.

To update a hook to a newer version:

```bash
openclaw hooks install <name>@<new-version>
```

This ensures that automatic dependency resolution never silently upgrades to a compromised version. Version changes are explicit and auditable.

## See Also

- [Trust-Tier Configuration](/gateway/security/trust-tiers) — configuring agent trust levels
- [Hooks](/automation/hooks) — hook usage and authoring guide
