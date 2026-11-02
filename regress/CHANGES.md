# Changes to the frozen verdicts (tools/regress.py)

A difference between a run of apc_verify on the corpus and regress/VERDICTS.json passes `tools/regress.py check` only
with a row of this table naming it: the bundle, the field (verdict, check:NAME, sha256, bundle_version, exit, verifier,
added, removed), the old and the new value exactly as `check` prints them, the SPEC section that motivates it (§N or
§N.M) and the reason. After the change is accepted, `tools/regress.py write` refreezes and the rows of that change are
removed from the table (a row that justifies nothing is refused by the full check).

| path | field | old | new | SPEC | reason |
|---|---|---|---|---|---|
