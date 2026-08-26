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

## Event ingestion

Use `InMemoryEventLog.ingest(intent, LifecycleEventIngress())` for in-memory
event creation. The log owns the run's sequence, prior hash, and lifecycle
state so construction and admission occur atomically. `append(event)` remains
available when an already constructed event must be verified and admitted.
The builder's event-ID and clock callbacks run inside the log's atomic critical
section, so they must be non-blocking and must not wait on other threads or
acquire locks in reverse order.

Use `parse_lifecycle_description()` from `rsd_canary.lifecycle`
when a typed lifecycle-description model is needed; use
`load_lifecycle_description()` for the compatible dictionary representation.

## License

[MIT](LICENSE)
