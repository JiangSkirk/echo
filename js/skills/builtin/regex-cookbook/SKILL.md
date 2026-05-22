---
id: regex-cookbook
name: Regex Cookbook
description: "Common regex patterns with explanations for everyday text matching tasks."
version: 1.0.0
author: JS Team
type: prompt
category: reference
tags: [regex, patterns, text-processing, reference]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: pattern
      type: string
      description: Text pattern to match or regex to explain
      required: false
---

# Regex Cookbook

Common regex patterns for everyday tasks.

## Patterns

| Task | Pattern | Notes |
|------|---------|-------|
| Email (simple) | `[\w.-]+@[\w.-]+\.\w+` | Lenient; RFC 5322 is too complex for regex |
| URL (http/s) | `https?://[^\s/$.?#].[^\s]*` | Basic extraction |
| IPv4 address | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | Validate 0-255 separately if needed |
| Date (YYYY-MM-DD) | `\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])` | ISO 8601 basic |
| UUID | `[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` | Version 1-5 |
| Credit card (Luhn) | `\b(?:\d{4}[- ]?){3}\d{4}\b` | Validate with Luhn algorithm after matching |
| Password (strong) | `^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$` | 8+ chars, mixed case, digit, symbol |
| HTML tag | `<[^>]+>` | Simple extraction; use parser for real HTML |
| Quoted string | `"[^"\\]*(?:\\.[^"\\]*)*"` | Handles escaped quotes |

## Tips

- Always anchor when validating full strings (`^...$`)
- Use non-capturing groups `(?:...)` when you do not need the match backreference
- Prefer lazy quantifiers (`.*?`) over greedy (`.*`) for shorter matches
- Test with edge cases: empty strings, Unicode, newlines

## Execution

When the user asks for a regex or needs one explained, provide a pattern from above or craft a new one with a clear breakdown of each part.
