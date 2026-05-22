---
id: docker-helper
name: Docker Helper
description: "Docker best practices, command reference, and troubleshooting guide."
version: 1.0.0
author: JS Team
type: prompt
category: devops
tags: [docker, containers, troubleshooting, devops]
trust_level: builtin
platforms: [macos, linux, windows]
metadata:
  parameters:
    - name: issue
      type: string
      description: Docker issue or command to help with
      required: false
---

# Docker Helper

Guide for Docker best practices and common troubleshooting scenarios.

## Quick Command Reference

| Task | Command |
|------|---------|
| Clean unused resources | `docker system prune -a` |
| Inspect container | `docker inspect CONTAINER` |
| Follow logs | `docker logs -f CONTAINER` |
| Shell into running container | `docker exec -it CONTAINER sh` |
| Build with no cache | `docker build --no-cache -t TAG .` |

## Best Practices

- Use multi-stage builds to minimize image size
- Pin base image tags (avoid `latest` in production)
- Run as non-root user (`USER` directive)
- Use `.dockerignore` to exclude unnecessary files
- One process per container
- Keep layers ordered by change frequency (least-changing first)

## Troubleshooting

1. **Container exits immediately**: Check `docker logs`; verify CMD/ENTRYPOINT
2. **Port not accessible**: Ensure `EXPOSE` + `docker run -p` mapping
3. **Permission denied**: Check volume mount ownership
4. **Image too large**: Use `docker history IMAGE` to inspect layer sizes
5. **Build cache issues**: Use `--no-cache` or reorganize Dockerfile layers

## Execution

When the user asks about Docker, provide concise commands and actionable advice based on the patterns above.
