# MoniTAal Gear-Control XML Properties as MITL

These formulas are the MITL translations used by
`MightyPPL/scripts/run_monitaal_benchmark_correctness.py`.

Source XML:
`MoniTAal/benchmark/gear-control-properties.xml`

The original XML uses uppercase event labels. The monitor formulas and converted
event streams use lowercase labels because the current MightyPPL frontend only
accepts lowercase proposition identifiers.

| XML positive template | XML negative template | MITL formula |
| --- | --- | --- |
| `CloseClutch` | `NotCloseClutch` | `G(closeclutch -> F[0,150] clutchisclosed)` |
| `OpenClutch` | `NotOpenClutch` | `G(openclutch -> F[0,150] clutchisopen)` |
| `ReqSet` | `NotReqSet` | `G(reqset -> F[0,300] gearset)` |
| `ReqNeu` | `NotReqNeu` | `G(reqneu -> F[0,200] gearneu)` |
| `SpeedSet` | `NotSpeedSet` | `G(speedset -> F[0,500] reqtorque)` |
| `test1` | `Nottest1` | `G(test1 -> F[0,900] reqtorque)` |

Each pair in the XML has the same response shape:

1. A trigger event starts a pending obligation and resets clock `x`.
2. A response event with `x <= bound` returns to the accepting base state.
3. The corresponding negative template accepts when the response occurs after
   the bound.

For example, `CloseClutch`/`NotCloseClutch` becomes:

```mitl
G(closeclutch -> F[0,150] clutchisclosed)
```

