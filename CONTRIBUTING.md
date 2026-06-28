# Contributing to ARGUS

Thank you for your interest in contributing to ARGUS. This project advances open LLM security tooling and welcomes contributions from the security research and AI safety communities.

## Ways to Contribute

- **Bug reports** — open an [issue](https://github.com/sunilgentyala/argus/issues) with reproduction steps
- **New attack strategies** — add entries to `argus/payloads/synthesizer.py` category prompts
- **New compliance frameworks** — extend `argus/compliance/mapper.py`
- **New target adapters** — subclass `argus.targets.base.Target`
- **Detection improvements** — enhance the LLM-as-judge rubric in `argus/detectors/llm_judge.py`
- **Documentation** — improve README, inline docs, or the GitHub Pages site
- **Tests** — add unit or integration tests under `tests/`

## Development Setup

```bash
git clone https://github.com/sunilgentyala/argus
cd argus
pip install -e ".[dev]"
pytest tests/unit/ -v
```

## Code Standards

- Python 3.11+, typed with `mypy --strict`
- Format with `ruff` (line length 100, configured in `pyproject.toml`)
- No new runtime dependencies without prior discussion in an issue
- All new modules must have at least one unit test

## Pull Request Guidelines

1. Fork the repo and create a feature branch from `main`
2. Keep changes focused — one logical change per PR
3. Ensure `pytest tests/unit/ -v` passes
4. Run `ruff check .` and fix any lint errors
5. Update relevant docs and the `CHANGELOG.md` if one exists
6. PRs that add new attack categories, targets, or compliance frameworks are especially welcome

## Responsible Disclosure

ARGUS is designed for **authorized security testing only**. If you discover a vulnerability in ARGUS itself, please report it via GitHub's private security advisory feature rather than opening a public issue.

## Contact

Questions about the project or contribution process: open a [GitHub Discussion](https://github.com/sunilgentyala/argus/discussions) or reach out via [sunil.gentyala@ieee.org](mailto:sunil.gentyala@ieee.org).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license.
