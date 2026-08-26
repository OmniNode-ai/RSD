# rsd-canary

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`rsd-canary` is a small Python library for creating, storing, and replaying
deterministic lifecycle events. It has no network client, service endpoint, or
deployment configuration.

## Development

Use Python 3.12 or newer and uv:

```sh
uv sync --all-groups
uv run pytest
uv run mypy src/ --strict
uv run ruff format --check src/ tests/
uv run ruff check src/ tests/
```

The bundled YAML file documents the states and transitions supported by the
library.

## License

[MIT](LICENSE)
