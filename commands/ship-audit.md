---
description: Pre-launch gate: run the staged ship audit and BLOCK on hard failures, WARN on soft ones.
allowed-tools: Read, Bash, Write, Grep, Glob
argument-hint: [project root] [framework hints like nextjs, django, express]
---
Invoke the `ship-audit` skill with this input: **$ARGUMENTS**

- No arguments: audit the current working directory; detect the framework
  from the source before the dynamic stage.
- With a framework hint: focus the dynamic checks (auth flow, live
  endpoints, error pages, CORS, migrations) on that framework's
  conventions, but verify each item in the code before calling it PASS.
- Always end with the verdict line `SHIP: BLOCK | SHIP: GO with N
  warnings | SHIP: GO` plus the `N items need manual verification`
  count.
