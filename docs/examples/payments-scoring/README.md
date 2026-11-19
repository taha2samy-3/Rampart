# Payments API: every resource that decides its score

One application, `payments-api`, and the five resources that change what a finding of it scores or how long it has to be fixed. The files are numbered in the order to apply them (the tenant first). The scores and deadlines they give, and how each is worked out, are in [docs/36](../../36-application-context-and-scoring.md) section 15; `internal/config/apply/scoring_example_test.go` applies these files and asserts those numbers.

```sh
for f in docs/examples/payments-scoring/*.yaml; do rampart apply -f "$f"; done
```

| File | Kind | Decides |
|---|---|---|
| `01-tenant.yaml` | Tenant | which namespaces are the tenant's |
| `02-clusterfeed.yaml` | ClusterFeed | which threat data exists (KEV, EPSS, exploit maturity) |
| `03-application.yaml` | Application | the facts about the product: criticality, exposure, data, controls |
| `04-riskpolicy.yaml` | RiskPolicy | how a score is worked out, and the band limits; its production factors read the branch name of the upload |
| `05-slapolicy.yaml` | SLAPolicy | how long you have, by band and criticality |

There is no `ScanSource` here: the scores do not depend on it (docs/36 section 15.5).
