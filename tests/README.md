# tests

End to end tests for input formats, one folder per area. Fixtures go in each folder's
`testdata/`. Unit tests for a single function stay next to the code in `internal/`.

| Folder | Covers |
|---|---|
| `sbom/` | Loading SBOMs. SPDX 2.2 from Yocto's create-spdx-2.2 so far. |

Run them with `go test ./tests/...`.
