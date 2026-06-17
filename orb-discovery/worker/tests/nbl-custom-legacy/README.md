## Nbl Custom Legacy Worker

A legacy counterpart to `nbl-custom`: it implements only the deprecated instance
`setup()` and omits the `describe()` classmethod. It exists so the worker's legacy
fallback path stays exercised — the worker constructs such a backend bare, reads its
metadata via `setup()` on the instance it then schedules, and attaches the ingest sink
afterwards.

`test_legacy_package.py` loads this package through the real `load_class` machinery and
drives it through `PolicyRunner.setup()` to prove the legacy path still works.

## Policy sample

``` yaml
policies:
    custom_legacy_1:
        config:
          package: nbl_custom_legacy
```
