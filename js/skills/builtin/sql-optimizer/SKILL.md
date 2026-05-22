---
id: sql-optimizer
name: SQL Optimizer
description: "SQL query optimization, indexing strategies, and performance tuning guide."
version: 1.0.0
author: JS Team
type: prompt
category: database
tags: [sql, database, optimization, indexing, performance]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: query
      type: string
      description: SQL query to analyze or optimize
      required: false
---

# SQL Optimizer

Guide for writing efficient SQL and optimizing slow queries.

## Indexing Rules

- Index columns used in `WHERE`, `JOIN`, `ORDER BY`
- Use composite indexes for multi-column filters (order matters: equality before range)
- Avoid indexing low-cardinality columns alone (e.g., boolean)
- Covering indexes include all selected columns to avoid table lookups

## Query Optimization

| Anti-Pattern | Better Approach |
|--------------|-----------------|
| `SELECT *` | Select only needed columns |
| `LIKE '%text%'` | Use full-text search or trigram indexes |
| `OR` on different columns | Use `UNION` or rewrite with `IN` |
| Functions on indexed columns (`WHERE YEAR(date) = 2024`) | Use range (`WHERE date >= '2024-01-01'`) |
| `NOT IN` with subqueries | Use `NOT EXISTS` or `LEFT JOIN / IS NULL` |
| Missing `LIMIT` on large scans | Add `LIMIT` or paginate with cursor/keyset |

## Diagnose with EXPLAIN

- `EXPLAIN ANALYZE` shows actual execution time
- Look for `Seq Scan` on large tables → add index
- Look for `Nested Loop` with high row counts → consider hash join hints

## Execution

When the user provides a SQL query, analyze it for the anti-patterns above and suggest concrete optimizations with index recommendations.
