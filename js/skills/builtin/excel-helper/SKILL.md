---
id: excel-helper
name: Excel Operations Assistant
description: Expert guide for reading, writing, merging, and creating Excel spreadsheets via the agent's office tools.
version: 1.0.0
author: JS Team
type: prompt
category: office
tags: [excel, spreadsheet, data, office]
trust_level: builtin
platforms: [macos, linux, windows]
---

# Excel Operations Guide

## Available Tools

- `excel_read`: Read data from an Excel file as JSON rows.
- `excel_write`: Write JSON rows into an Excel file at a specific cell.
- `excel_merge`: Copy data from one Excel file into another at a specific location.
- `excel_create`: Create a new blank Excel file with optional headers.

## Best Practices

### Reading Data

1. Use `excel_read` first to inspect the structure of an unknown file.
2. Specify `sheet` if the file has multiple sheets.
3. Use `start_row`, `end_row`, `start_col`, and `end_col` to read only what you need.

### Writing Data

1. Data must be a JSON array of rows: `[["Name", "Age"], ["Alice", 30]]`.
2. `start_cell` controls where data lands, for example `"E1"` writes to column E.
3. Set `append=true` to add rows at the end without overwriting existing data.

### Merging Data

Example: copy rows 2-10 from `Sheet1` of `A.xlsx` into `B.xlsx` starting at `E3`.

```yaml
source_path: A.xlsx
target_path: B.xlsx
source_range: A2:D10
target_start_cell: E3
include_header: false
```

Key points:

- `source_range` uses Excel notation like `A1:D10`.
- `target_start_cell` is where the top-left cell of the source range lands.
- Set `include_header: false` if the first source row is data.
- Read both files first to understand their structure before merging.

### Creating Files

1. Use `excel_create` to make a new file with headers.
2. Use `excel_write` to populate data.

## Common Patterns

### Extract Specific Columns

1. Read the source file.
2. Inspect the JSON output to identify column indices.
3. Write only the needed columns to a new file.

### Combine Multiple Files

1. Create a new file with unified headers.
2. Merge each source file into the target at the next empty row.
3. Verify the final sheet with `excel_read`.

### Insert Data Between Columns

1. Read the target file to understand current structure.
2. Use `excel_merge` with `target_start_cell` set to the insertion point.
3. If inserting in the middle, shift existing data by reading and writing the affected columns.

## Error Handling

- Verify files exist before reading.
- Check sheet names when a file has multiple sheets.
- Treat empty cells as empty strings in JSON output.
