---
id: pdf-helper
name: PDF Generation Assistant
type: prompt
category: office
description: Expert guide for generating PDF documents from tabular data using the agent's office tools.
tags: [pdf, report, table, export, office]
platforms: [macos, linux, windows]
---

# PDF Generation Guide

## Available Tool

- `pdf_generate` — Create a PDF file from JSON tabular data

## Usage

### Data Format
Provide data as a JSON array of rows. The first row is treated as the table header.

```json
[
  ["Name", "Department", "Score"],
  ["Alice", "Engineering", 95],
  ["Bob", "Design", 88],
  ["Carol", "Marketing", 92]
]
```

### Parameters
- `path` — Output file path (e.g. `report.pdf`)
- `title` — Document title shown at the top
- `data` — JSON string of rows
- `page_size` — `"A4"` (default) or `"LETTER"`

### Best Practices
1. **Always include a header row** as the first element of `data`
2. **Keep cell content short** — long text may overflow table cells
3. **Pre-process data** before PDF generation:
   - Round numbers to 2 decimal places
   - Format dates as strings
   - Replace `null` with `""` or `"N/A"`
4. **For large datasets** (>50 rows), consider:
   - Splitting into multiple PDFs
   - Using landscape orientation (not yet supported, use Excel instead)
   - Summarizing data first

## Common Patterns

**Pattern 1: Export Excel data as PDF**
1. `excel_read` to get data from Excel
2. Parse the JSON output
3. `pdf_generate` with the same data

**Pattern 2: Generate a report from calculations**
1. Perform calculations or data aggregation
2. Format results as a JSON array
3. `pdf_generate` with an appropriate title

**Pattern 3: Combine multiple tables into one PDF**
Currently `pdf_generate` supports one table per PDF. For multi-table documents:
- Generate separate PDFs and inform the user to combine them externally, or
- Use Excel as an intermediate format (create sheets for each table)

## Limitations
- Single table per PDF
- Portrait orientation only
- No custom styling beyond the built-in grid header style
- Images are not supported
