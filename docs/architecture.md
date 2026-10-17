# Amaura Architecture

Amaura is built as a verification runtime, not a monolithic autonomous agent.

```
+-------------------------------------------------------------+
|                     User Interface / CLI                    |
|       amaura init / verify / audit / claim-check / report   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                 Task & Claim Compiler                       |
|           Requirements, Claims, Acceptance Criteria         |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                 Verification Planner                        |
|       Selects tests, builds, static AST checks, citations   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|             Isolated Execution & Verification               |
|          Safe Subprocess, Timeouts, Secret Redaction        |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|               Evidence Graph & Provenance                   |
|       Claim -> Obligation -> Check -> Exec -> Ev -> Finding |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|               Independent Verdict Engine                    |
|           Deterministic fail-closed rule evaluation         |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
|                    Audit Package                            |
|             Markdown report & JSON audit ledger             |
+-------------------------------------------------------------+
```

## Traceability Chain
1. **Claim**: What the agent or user says is true.
2. **Obligation**: What must be observed to support it.
3. **Check**: The method selected to test it.
4. **Execution**: The exact run, inputs, environment, and permissions.
5. **Evidence**: Output, source passage, test result, dataset, or artifact.
6. **Finding**: What the evidence supports or contradicts.
7. **Verdict**: Conclusion with scope and residual uncertainty.
