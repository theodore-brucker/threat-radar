# Working in this repository

- Front-end changes (anything under `app/static/`): read `DESIGN.md` and
  `PRODUCT.md` first and follow them. Colours, radii, spacing and type come
  from `app/static/css/tokens.css` only. Preview with
  `python tools/demo_data.py /tmp/radar-demo` and the uvicorn command in
  `DESIGN.md`, and compare against `docs/design/`.
- Attacker-supplied strings reach the DOM through `h()` and `textContent`
  only. `tests/test_frontend.py` fails on any HTML sink.
- No build step and no npm at runtime. Third-party files are vendored and
  listed in `THIRD_PARTY.md`.
- Run `python -m pytest -q` and `ruff check .` before pushing.
