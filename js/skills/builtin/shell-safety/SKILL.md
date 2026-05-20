---
id: shell-safety
name: Shell Command Safety Checker
description: "Analyze shell commands for dangerous patterns before execution."
version: 1.0.0
author: JS Team
type: prompt
category: devops
tags: [security, shell, safety, review]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: command
      type: string
      description: The shell command to analyze for safety
      required: true
---

# Shell Command Safety Checker

Analyze shell commands for dangerous patterns.

## Danger Patterns

Flag these as CRITICAL:
- `rm -rf /` or `rm -rf /*` or `rm -rf ~`
- `dd if=/dev/zero of=/dev/sda`
- `curl ... | sh` or `wget ... | bash` (pipe to shell)
- `:(){ :|:& };:` (fork bomb)
- `chmod -R 777 /`
- `mkfs.` on system partitions
- `> /dev/sd[a-z]` (direct disk overwrite)

Flag these as HIGH:
- `curl | sudo sh`
- `eval $(curl ...)`
- Recursive `chown` on system dirs
- `find / -name ... -exec rm {} \;`

Flag these as MEDIUM:
- Missing quotes around variables (`$VAR` vs `"$VAR"`)
- `rm -rf $DIR` (variable could be empty)
- Hardcoded credentials in commands

## Input Parameters

- `command` (required): The shell command to analyze

## Output Format

```
[SEVERITY] PATTERN: Description
Command: the exact command
Mitigation: safer alternative
```

If safe, output: `[OK] No dangerous patterns detected.`

## Execution

Analyze the provided `command` against all danger patterns listed above. Output findings in the format specified. If no dangerous patterns are found, output `[OK] No dangerous patterns detected.`
