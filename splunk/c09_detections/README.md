# C09 detection app

Requires an active Splunk Enterprise or Developer license with scheduled-search
capability. The current source enables seven scheduled alerts; deployment and
scenario acceptance must be verified on the target instance. This change is
C09-ALERTS-01 revision 1, not a v3.1 release or an independent review result.

Copy this `c09_detections` directory onto the Splunk host under
`/opt/splunk/etc/apps/` after backing up any existing app and its permissions.
Reload or restart Splunk using the deployment's normal service procedure.
The searches expect index `c09` and fields from
[telemetry schema v1.0](../../docs/telemetry-schema.md). No forwarder settings are
included. `metadata/default.meta` exports the knowledge objects system-wide,
with read access for all roles and write access for admins. Confirm the effective
owner and permissions on deployment.

## Triggering and cadence

Every search has `enableSched = 1`, `counttype = number of events`,
`relation = greater than`, and `quantity = 0`. The SPL already filters to
suspicious result rows, so a nonempty result triggers the alert. `alert.track = 1`
forces local Triggered Alerts tracking, `alert.digest_mode = 1` groups the run's
results, and explicit `action.email = 0`, `action.script = 0` and
`action.webhook = 0` keep those notification actions disabled.
There is no email, webhook, script, or external notification destination.

| Searches | Schedule | Lookback |
|---|---|---|
| D1, D2, D4, D5 | Every five minutes | Five minutes |
| D3a | Every ten minutes | Ten minutes |
| D3b | Every five minutes | Ten minutes |
| D6 | Every minute | One minute |

All windows end at `now`; SPL, thresholds, windows and cron cadence are unchanged
from the v3.0 package. Fixed buckets can split bursts, events arriving after a
window closes can be missed, and overlapping D3b windows can return the same
join more than once. No deduplication or scheduling-latency correction is claimed.
D3b and D4 remain endpoint-correlation heuristics; D4 also needs handoff context
that can fall outside the dispatch window. See the
[detection limitations](../../detections/README.md).

## Validation

Validate the installed settings with `splunk btool savedsearches list --app=c09_detections --debug` under the Splunk service account. Check scheduler
logs for each named search's scheduled time, dispatch time, status, SID and result
count, and check local alert records for nonempty runs. An enabled flag or a
manual search alone does not establish scheduled alerting.

Run each relevant malicious and benign case against the existing instrumented
lab servers. Preserve per-case time bounds separately from the committed
`phase3/attack/last_run.jsonl` historical fixture. The default eight-second gaps
do not isolate five- or ten-minute lookbacks. Account for prior authentication,
game timeouts, ingestion delay and bucket boundaries. Record failures and stop
for a revised brief if SPL or window changes are required.

The installed Splunk 10.4.3 `savedsearches.conf.spec` was read to verify
`enableSched`, `counttype`, `relation`, `quantity` and `alert.track` semantics.
See [this change's validation record](../../docs/c09-alerts-01-validation.md)
for actual runtime evidence and acceptance status.

## Rollback

Disable only these seven C09 schedules and restore the backed-up app and
permissions. If the app did not exist before deployment, move it outside the
active apps directory rather than removing evidence. Reload/restart if required,
then verify service health and unrelated saved searches. Do not delete indexed
telemetry as part of rollback.

Runtime verification for revision 1 completed on 2026-10-16: seven positive/negative
pairs and SID-matched local alert records. Independent review, user acceptance
and v3.1 release remain pending; see the validation record for evidence and limits.
