---
id: excel-helper
name: Excel Operations Assistant
type: prompt
category: office
description: Expert guide for reading, writing, merging, and creating Excel spreadsheets via the agent's office tools.
tags: [excel, spreadsheet, data, office]
platforms: [macos, linux, windows]
---

# Excel Operations Guide

## Available Tools

- `excel_read` — Read data from an Excel file as JSON rows
- `excel_write` — Write JSON rows into an Excel file at a specific cell
- `excel_merge` — Copy data from one Excel file into another at a specific location
- `excel_create` — Create a new blank Excel file with optional headers

## Best Practices

### Reading Data
1. Use `excel_read` first to inspect the structure of an unknown file
2. Specify `sheet` if the file has multiple sheets
3. Use `start_row`, `end_row`, `start_col`, `end_col` to read only what you need

### Writing Data
1. Data must be a JSON array of rows: `[["Name", "Age"], ["Alice", 30]]`
2. `start_cell` controls where data lands (e.g. `"E1"` writes to column E)
3. Set `append=true` to add rows at the end without overwriting existing data

### Merging Data (Copy A → B)
This is the most common advanced operation:

```
Scenario: Copy rows 2-10 from Sheet1 of A.xlsx into B.xlsx starting at cell E3

Parameters:
  source_path: "A.xlsx"
  target_path: "B.xlsx"
  source_range: "A2:D10"
  target_start_cell: "E3"
  include_header: false
```

**Key points for merge:**
- `source_range` uses Excel notation like `"A1:D10"`
- `target_start_cell` is where the top-left cell of the source range lands
- Set `include_header: false` if the first row of source_range is data (not headers)
- Always read both files first to understand their structure before merging

### Creating Files
1. Use `excel_create` to make a new file with headers
2. Then use `excel_write` to populate data

## Common Patterns

**Pattern 1: Extract specific columns**
1. `excel_read` the source file
2. Inspect the JSON output to identify column indices
3. `excel_write` only the needed columns to a new file

**Pattern 2: Combine multiple files**
1. `excel_create` a new file with unified headers
2. For each source file: `excel_merge` into the target with appropriate `target_start_cell`
3. Use `append` semantics by calculating the next empty row

**Pattern 3: Insert data between columns**
1. Read the target file to understand current structure
2. Use `excel_merge` with `target_start_cell` set to the insertion point
3. If inserting in the middle, you may need to shift existing data by reading → writing shifted columns

## Error Handling
- Always verify files exist before reading
- Check sheet names if the file has multiple sheets
- Handle empty cells (returned as `""` in JSON)
