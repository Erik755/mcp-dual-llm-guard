# Contributing

Thanks for your interest! This project values **correctness over features**.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

Run these locally before opening a PR. The GitHub Actions workflow runs the same
gates but is **manual-only** (`workflow_dispatch`, from the Actions tab).

```bash
ruff check . && ruff format --check .   # lint + formatting
mypy                                    # --strict over src/, tests/, examples/
pytest --cov --cov-fail-under=95        # unit, integration (real MCP SDK) and adversarial tests
```

## Guidelines

- Every security-relevant change needs a test that fails without it. Attacks go
  in `tests/test_adversarial.py` and must assume **fully obedient models**.
- Never format untrusted values into exception messages, `repr`, or audit events.
- Keep the privileged prompt constructible from trusted parts only.
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `test:`, `docs:` …).
