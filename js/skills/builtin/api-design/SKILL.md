---
id: api-design
name: API Design Guide
description: "REST API design guidelines and OpenAPI specification best practices."
version: 1.0.0
author: JS Team
type: prompt
category: software-development
tags: [api, rest, openapi, design, http]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: endpoint
      type: string
      description: API endpoint or spec to review
      required: false
---

# API Design Guide

Guidelines for designing clean, consistent REST APIs.

## URL & HTTP Conventions

| Action | Method | URL Pattern |
|--------|--------|-------------|
| List | GET | `/resources` |
| Retrieve | GET | `/resources/{id}` |
| Create | POST | `/resources` |
| Update | PUT/PATCH | `/resources/{id}` |
| Delete | DELETE | `/resources/{id}` |

- Use plural nouns (`/orders`, not `/order`)
- Nest sub-resources: `/orders/{id}/items`
- Avoid verbs in URLs; use HTTP methods instead

## Response Standards

- Use correct status codes: `200`, `201`, `204`, `400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`
- Return consistent error envelope: `{ "error": { "code": "...", "message": "...", "details": [...] } }`
- Support filtering (`?status=active`), sorting (`?sort=-created_at`), and pagination (`?cursor=...` or `?page=`)

## OpenAPI Tips

- Version your spec (`openapi: 3.0.0`)
- Reuse schemas with `#/components/schemas/`
- Define all response codes including errors
- Use `enum` for constrained string values
- Add `example` fields for clarity

## Execution

When the user describes or shares an API design, review it against the conventions above and suggest improvements.
