---
id: arxiv-research
name: arXiv Paper Research
description: "Search and summarize academic papers from arXiv via their free API."
version: 1.0.0
author: JS Team
type: prompt
category: research
tags: [arxiv, papers, academic, research, science]
trust_level: builtin
platforms: [macos, linux, windows]
prerequisites:
  commands: [curl]
---

# arXiv Research

Search and retrieve academic papers from arXiv via their free REST API.

## Quick Reference

| Action | Command |
|--------|---------|
| Search papers | `curl "https://export.arxiv.org/api/query?search_query=all:QUERY&max_results=5"` |
| Get specific paper | `curl "https://export.arxiv.org/api/query?id_list=2402.03300"` |

## Searching Papers

The API returns Atom XML. Parse with Python for clean output.

### Clean search

```bash
curl -s "https://export.arxiv.org/api/query?search_query=all:QUERY&max_results=5&sortBy=submittedDate&sortOrder=descending" | python3 -c "
import sys, xml.etree.ElementTree as ET
ns = {'a': 'http://www.w3.org/2005/Atom'}
root = ET.parse(sys.stdin).getroot()
for i, entry in enumerate(root.findall('a:entry', ns)):
    title = entry.find('a:title', ns).text.strip().replace('\n', ' ')
    arxiv_id = entry.find('a:id', ns).text.strip().split('/abs/')[-1]
    published = entry.find('a:published', ns).text[:10]
    authors = ', '.join(a.find('a:name', ns).text for a in entry.findall('a:author', ns))
    summary = entry.find('a:summary', ns).text.strip()[:200]
    print(f'{i+1}. [{arxiv_id}] {title}')
    print(f'   Authors: {authors} | Published: {published}')
    print(f'   Summary: {summary}...')
    print()
"
```

## When to Use

- User asks about research papers or academic sources
- Need to cite or summarize scientific work
- User provides an arXiv ID
