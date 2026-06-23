# Cyber Arena — Challenge Warehouse

Standalone home for cyber-arena challenge contributions. Consumed by
[`cyber-arena-orche`](https://github.com/cyber-arena-ai/cyber-arena-orche) as a
git submodule mounted at `challenge-warehouse/`.

## Layout

```
<contributor>/<challenge>/
```

One directory per contributor (their handle), then one package per challenge.
The contributor layer is purely organizational — it groups credit; it is **not**
a Python package and never appears in an import path. The framework appends each
`<contributor>/` dir to `challenges.__path__`, so a challenge is imported as
`challenges.<challenge>` regardless of who authored it. (This is why contributor
handles that aren't valid Python identifiers, e.g. `3rdn4Li`, are fine.)

```
3rdn4Li/
├── treasury/
│   ├── __init__.py          # exports exactly one concrete Challenge subclass
│   ├── challenge.py
│   ├── build.py             # build_image() -> docker tag
│   ├── flag_handler.py
│   ├── functionality_test.py
│   ├── image/               # docker build context for the vulbox
│   └── requirements.txt     # host-side checker/flag-handler deps (optional)
└── ...
```

## Adding a challenge

1. Create `your-handle/<challenge>/` following an existing one (e.g.
   `YueyangPan/nautilus_ico/` is the reference) and the authoring SOP in the
   framework repo (`docs/CHALLENGE_AUTHORING_SOP.md`).
2. The package must export exactly one concrete `Challenge` (from
   `challenges.interface`, provided by the framework) with a unique kebab-case
   `name` and a `build.py:build_image()`.
3. If your checker/flag-handler imports third-party libs host-side, list them in
   `your-handle/<challenge>/requirements.txt`.
4. Open a PR here. Slugs must be globally unique across all contributors.

## Notes

- The `Challenge` ABC / `interface` lives in the framework (`challenges.interface`),
  not here — it's the contract, not a contribution. Challenges import it directly.
- Large vendored upstream sources are challenge-local and gitignored (see
  `nautilus_ico/vendor/`, materialized by the framework's `scripts/sync_nautilus.sh`).
