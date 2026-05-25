---
id: pdf-helper
name: PDF Generation Assistant
description: Expert guide for generating PDF documents from tabular data using the agent's office tools.
version: 1.0.0
author: JS Team
type: prompt
category: office
tags: [pdf, report, table, export, office]
trust_level: builtin
platforms: [macos, linux, windows]
---

# PDF Generation Guide

## Available Tool

- `pdf_generate`: Create a PDF file from JSON tabular data.

## Data Format

Provide data as a JSON array of rows. The first row is treated as the table header.

```json
[
  ["Name", "Department", "Score"],
  ["Alice", "Engineering", 95],
  ["Bob", "Design", 88],
  ["Carol", "Marketing", 92]
]
```

## Parameters

- `path`: Output file path, for example `report.pdf`.
- `title`: Document title shown at the top.
- `data`: JSON string of rows.
- `page_size`: `A4` or `LETTER`.

## Best Practices

1. Always include a header row as the first element of `data`.
2. Keep cell content short because long text may overflow table cells.
3. Pre-process data by rounding numbers, formatting dates as strings, and replacing `null` with `""` or `"N/A"`.
4. For large datasets, summarize first or split output into multiple PDFs.

## Common Patterns

### Export Excel Data as PDF

1. Use `excel_read` to get data from Excel.
2. Parse the JSON output.
3. Run `pdf_generate` with the same data.

### Generate a Calculation Report

1. Perform calculations or aggregation.
2. Format results as a JSON array.
3. Generate a PDF with a clear title.

### Multiple Tables

`pdf_generate` supports one table per PDF. For multi-table documents, create separate PDFs or use Excel as an intermediate format.

## Limitations

- Single table per PDF.
- Portrait orientation only.
- Built-in table styling only.
- Images are not supported.
