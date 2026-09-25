# Security Policy

`mcp-dual-llm-guard` is a security-focused research/reference implementation.
Reports of bypasses are very welcome — they are the most valuable contribution
this project can receive.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please **do not open a public issue** for an exploitable bypass. Instead use
GitHub's private vulnerability reporting for this repository
(*Security → Report a vulnerability*).

Please include:

- a minimal reproduction (ideally a failing pytest in the style of `tests/test_adversarial.py`);
- which invariant is broken (see below);
- the Python version and `pip freeze` output.

You can expect an acknowledgement within 7 days.

## Security invariants

A report is in scope if it demonstrates, **without modifying library code or
reaching into private attributes**, any of the following:

1. Text from an untrusted source (tool output, MCP tool description, quarantined
   LLM output) reaching a message sent to the privileged LLM.
2. A value with untrusted provenance being bound to a tool argument whose policy
   is `UntrustedFlow.DENY` (or `REQUIRE_APPROVAL` without approval).
3. Resolution of a symbolic pointer by any component other than the holder of the
   memory's declassification capability.
4. A tool call that is not in the validated plan, or a plan that references a
   tool outside the registry, being executed.
5. A changed MCP tool manifest being accepted against an existing pin.
6. Untrusted content appearing in exception messages or the audit log.

## Out of scope (documented limitations)

- Code running in the same Python process: Python has no hard encapsulation,
  so in-process attackers can always read private state. The capability model
  defends against *accidental* and *LLM-driven* misuse.
- Attacks that only affect the *content* of untrusted-derived text shown to the
  user (e.g. a misleading summary) — the pattern constrains actions and data
  flows, not the truthfulness of text.
- Heuristic misses of `PoisoningScanner`: it is a tripwire; the architectural
  defence (operator-authored descriptions, pinning) is what is guaranteed.

See the *Limitations* section of the README for details.
