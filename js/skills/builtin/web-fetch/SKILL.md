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
metadata:
  parameters:
    - name: url
      type: string
      description: The URL to fetch content from
      required: true
    - name: max_length
      type: integer
      description: Maximum characters to return
      required: false
---

# Web Content Fetcher

Fetch content from URLs and return clean text.

## When to Use

- User provides a URL and asks "what does this page say?"
- Need to summarize an article or documentation
- Extract specific information from a webpage

## How to Use

Use `curl` to fetch the page, then strip HTML. The URL is read from `JS_SKILL_ARGS`:

```python
import json, os, re, subprocess, sys

args = json.loads(os.environ.get("JS_SKILL_ARGS", "{}"))
url = args.get("url", "")
max_length = int(args.get("max_length", 5000))

if not url:
    print("Error: No URL provided")
    sys.exit(1)

# Validate URL scheme
if not url.startswith(("http://", "https://")):
    print("Error: URL must start with http:// or https://")
    sys.exit(1)

# Block private IPs
if any(url.startswith(prefix) for prefix in ["http://127.", "http://192.168.", "http://10.", "http://0.", "http://localhost"]):
    print("Error: Private IP addresses are not allowed")
    sys.exit(1)

result = subprocess.run(
    ["curl", "-s", "-L", "--max-time", "30", "-A", "JS-Agent/1.0", url],
    capture_output=True, text=True
)
if result.returncode != 0:
    print(f"Error: Failed to fetch {url}: {result.stderr}")
    sys.exit(1)

html = result.stdout
text = re.sub(r'<[^>]+>', ' ', html)
text = re.sub(r'\s+', ' ', text).strip()
print(text[:max_length])
```

## Safety Rules

- Never fetch private IPs (127.0.0.1, 192.168.x.x, 10.x.x.x)
- Respect robots.txt
- Limit output to 5000 chars
