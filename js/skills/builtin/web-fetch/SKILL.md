---
id: web-fetch
name: Web Content Fetcher
description: "Fetch and extract text content from URLs with retry and rate limiting."
version: 1.0.0
author: JS Team
type: prompt
category: research
tags: [web, fetch, curl, http]
trust_level: builtin
platforms: [macos, linux, windows]
prerequisites:
  commands: [curl]
---

# Web Content Fetcher

Fetch content from URLs and return clean text.

## When to Use

- User provides a URL and asks "what does this page say?"
- Need to summarize an article or documentation
- Extract specific information from a webpage

## How to Use

Use `curl` to fetch the page, then strip HTML:

```bash
curl -s -L "$URL" | python3 -c "
import sys, re
html = sys.stdin.read()
text = re.sub(r'<[^>]+>', ' ', html)
text = re.sub(r'\s+', ' ', text).strip()
print(text[:5000])
"
```

## Safety Rules

- Never fetch private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x)
- Respect robots.txt
- Limit output to 5000 chars
