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
metadata:
  parameters:
    - name: query
      type: string
      description: Search query term or arXiv paper ID
      required: true
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
try:
    root = ET.parse(sys.stdin).getroot()
    entries = root.findall('a:entry', ns)
    if not entries:
        print('No results found for this query.')
        sys.exit(0)
    for i, entry in enumerate(entries):
        title_el = entry.find('a:title', ns)
        title = (title_el.text or '').strip().replace('\n', ' ') if title_el is not None else 'N/A'
        id_el = entry.find('a:id', ns)
        arxiv_id = (id_el.text or '').strip().split('/abs/')[-1] if id_el is not None else 'N/A'
        pub_el = entry.find('a:published', ns)
        published = (pub_el.text or '')[:10] if pub_el is not None else 'N/A'
        authors_els = entry.findall('a:author', ns)
        authors = ', '.join(
            (a.find('a:name', ns).text or 'Unknown') for a in authors_els
        ) if authors_els else 'Unknown'
        sum_el = entry.find('a:summary', ns)
        summary = (sum_el.text or '').strip()[:200] if sum_el is not None else 'N/A'
        print(f'{i+1}. [{arxiv_id}] {title}')
        print(f'   Authors: {authors} | Published: {published}')
        print(f'   Summary: {summary}...')
        print()
except Exception as e:
    print(f'Error parsing arXiv response: {e}', file=sys.stderr)
    sys.exit(1)
"
```

## When to Use

- User asks about research papers or academic sources
- Need to cite or summarize scientific work
- User provides an arXiv ID
