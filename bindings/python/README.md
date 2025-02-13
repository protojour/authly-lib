# Authly Python bindings

Python bindings for `authly-client`, enabling easy service initialization and access control interaction with [Authly](https://github.com/protojour/authly) IAM.

## Installation

```bash
pip install authly # (soon)
```

## Usage

TBA

## Development

You need [maturin](https://github.com/PyO3/maturin), [uv](https://docs.astral.sh/uv/) and [Docker Compose](https://docs.docker.com/compose/).

Set up development dependencies and virtual env with:

```bash
uv sync
```

Run Authly server with OpenBao secrets store and initial prelude stages with:

```bash
docker compose up
```

`protojour/authly:dev` must be built from [Authly](https://github.com/protojour/authly) `just` tasks for now.

Before restarting, run:

```bash
docker compose down -v
```

After changes to Rust code, run:

```bash
maturin dev
```

Run tests with:

```bash
uv run pytest -svv
```
