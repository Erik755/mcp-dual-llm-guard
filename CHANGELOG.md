# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `examples/live_llm_demo.py` no longer crashes with a traceback when `OPENAI_API_KEY`
  is unset. It now prints how to set the key (or use `--no-key` for local servers),
  points to the offline `examples/email_injection_demo.py`, and exits with code 1.
