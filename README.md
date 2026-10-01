# threat-hunter-toolkit

Small utilities for the detection engineering side of the job: turn a Sigma rule
into a backend query, check what ATT&CK coverage a rule directory actually has,
and map field names between SIEMs.

The recurring theme is refusing to guess. A converter that emits a
plausible-looking query with a subtle translation error is worse than one that
stops and tells you what it could not handle, because the first kind fails
silently in production.

## Quick start

```bash
git clone https://github.com/shadow-ciper/threat-hunter-toolkit
cd threat-hunter-toolkit
pip install -e .

huntkit convert samples/rules/windows_lsass_access.yml --explain
huntkit coverage samples/rules
huntkit fields --rule samples/rules/network_tor_orport.yml --backend esql
```

## Coverage report

The headline output. It parses every rule in a directory, maps tags to
techniques, and shows where the gaps are:

```
ATT&CK coverage against bundled snapshot v14 (partial: 40 techniques)
  techniques covered    : 6/43  (14.0%)
  rules without a technique tag : 0
  rules that failed to parse     : 0

tactic                    covered
initial-access             0/5    .....
execution                  1/5    #....
credential-access          1/5    #....
command-and-control        1/6    #.....

techniques with no rule in this directory
  T1003      OS Credential Dumping (credential-access)
  T1110.003  Password Spraying (credential-access)
  ...
```

Rules that fail to parse are listed separately rather than skipped silently —
a malformed rule that quietly drops out of a coverage report makes the report
look better than the reality.

## The three subcommands

**`convert`** renders a Sigma rule as Splunk SPL or Elastic ES|QL. Field
modifiers are translated properly: `CommandLine|contains` becomes
`CommandLine="*foo*"`, `Image|endswith` becomes `Image="foo$"`. Passing the
modifier through as part of the field name produces a query that parses fine
and matches nothing, which is the bug this subcommand exists to avoid.

Conditions using aggregation (`| count() > 5`) or `near` are **refused**, not
approximated. So is `|re` when targeting SPL, which has no direct equivalent.

**`coverage`** is described above. `--json` for tooling.

**`fields`** maps canonical field names to backend-specific ones and reports
what it could not map. Every environment names things differently, and this is
where translation mistakes creep in.

```
$ huntkit fields --rule samples/rules/windows_lsass_access.yml --backend esql
canonical                -> esql
  EventID                  (no mapping for: EventID)
```

## Design decisions worth knowing

**Only explicit `attack.tXXXX` tags count as coverage.** Inferring a technique
from a rule's title would produce confident-looking but wrong mappings. A
coverage report that overstates coverage is the opposite of useful.

**Coverage is measured against a bundled snapshot, not live ATT&CK.** The
technique list ships in-tree (partial, v14-era, ~43 entries) so the tool runs
offline. The version is printed in the report header. It is not a full ATT&CK
matrix and the report does not pretend to be.

**Unmapped fields are reported, not defaulted.** When a rule uses `EventID` and
the map has no entry, the tool says so. Guessing `event.code` would be wrong on
half the deployments.

## Known limitations

- **Partial Sigma support.** No `aggregate`, no `near`/`| by` proximity, no
  transformation blocks, no correlation across data sources.
- **`or` between multiple selections is treated as `and`.** Conditions that join
  selections with `or` are combined conjunctively. This is the safe direction
  (fewer results, never a miss) but it is not a correct translation.
- **Coverage snapshot is partial.** 43 techniques, not the full matrix.
- **Field map is small.** 13 canonical fields covering common cases only.
- **No Sigma test-case validation.** It does not check that a rule's tests pass
  against sample events, which is what Sigma's own tooling is for.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

34 tests. Several are regression tests for translation bugs found during
development — each modifier's wildcard placement has one, because getting
`endswith` to render as `contains` produces a query that runs and quietly
returns too much, which is the kind of bug that survives review.

## Layout

```
src/huntkit/
  sigma.py      Sigma parsing into rule objects
  querygen.py   Sigma -> SPL/ES|QL translation
  attack.py     technique table and coverage reporting
  fieldmap.py   canonical -> backend field mapping
  cli.py        subcommand dispatch
samples/rules/  five rules used by tests and the coverage demo
tests/
```