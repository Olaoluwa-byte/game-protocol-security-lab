# C09-ALERTS-01 revision 1 validation

Status: implemented and runtime validation verified on 2026-10-16; ready for
Claude independent review. User acceptance and v3.1 release remain pending.
This record does not authorize or claim a release.

## Scope and binding

The user approved revision 1 on 2026-10-16 at 11:25 EDT. Base commit:
`85ec9590ba73f5b31e1736277ba0251e62bd5e28`. Implementation branch:
`chore/c09-scheduled-alerts`. The isolated checkout was cloned locally from the
canonical public-history checkout. Its origin points to that local checkout;
no push or external branch/PR/release action is authorized. The canonical
checkout's untracked instruction file and original private checkout are preserved.

Saved-search configuration SHA-256:
`745de3e4474a9174642a6eaa38e6f6947843d4505b76e5ef799a4aaf990620f1`.
The source and deployed configuration hashes were observed to match.

The seven SPL strings, dispatch windows, thresholds embedded in the SPL, and
cron schedules are byte-equivalent as parsed to the approved base. Scheduling,
count-based conditions and local alert tracking are enabled. Email, script and
webhook action flags are explicitly disabled. The initial implementation's
empty `actions` key had no entry in the installed specification; it was replaced
with supported generic action flags before scenario acceptance. The initial
and final configuration states must not be conflated.

## Configuration and rollback evidence

The target is UbuntuDesk (`yuji-VirtualBox`), Splunk 10.4.3. Installed
`/opt/splunk/etc/system/README/savedsearches.conf.spec` was read to verify
`enableSched`, `counttype`, `relation`, `quantity`, `alert.track`, and generic
`action.<action_name>` settings.

The C09 app was absent before deployment. Root-only backup:
`/var/backups/c09-alerts-01-20261016/before.tgz` (mode 0600, parent mode 0700).
SHA-256: `680b70e2904e18d3181ee0d628415a5206d2643f5addf2bab34a03068ccbc8d2`.
It preserves the pre-existing search app's saved searches and local metadata.
Subsequent byte comparisons showed both unchanged. The new C09 files are owned
by the `splunk` OS account, with configuration files mode 0640 and directories
mode 0750. The existing metadata policy exports objects system-wide, read to
all roles and write to admins; it was not expanded by this change.

The scheduler records the C09 search owner as `nobody`, app `c09_detections`.
Effective permissions and successful execution are observed separately from
the OS file owner. The service returned active/running after reload; Web returned
HTTP 200. Startup produced localhost postgres/SPL2 connection-refused messages through
11:38:39 EDT. A later log scan found no ERROR entries from 11:40 onward,
and the final service check was active with Web HTTP 200.
A CLI search also reported pre-existing disabled certificate hostname validation;
this task does not change TLS settings.

## Validation method

A Python ConfigParser comparison against `git show HEAD:<savedsearches path>`
asserted seven stanzas, unchanged SPL/windows/cron, enabled schedules, the
nonempty-result trigger and local tracking, and disabled outbound notification
actions. `git diff --check` passed. No server-code changes were made, so the
telemetry unit suite is not substituted for live scheduler validation.

The two existing instrumented servers were initially stopped. They were started
with the documented Python commands, existing key/key-id, existing JSONL mounts,
and no server-code replacement or state reset. A preliminary benign attempt
before startup timed out waiting for HELLO_ACK; it is a failed attempt, not a
successful case. Subsequent successful generator cases record start/end epochs
outside the committed historical `last_run.jsonl` fixture.

D3a's benign case was isolated first, before other successful-authentication
cases. It produced two successful authentications on one endpoint; the 11:40 EDT
scheduled dispatch returned zero rows. Remaining benign cases were then run
together after that boundary. Four distinct failed accounts in total remain
below D2's five-account threshold, each endpoint/account remains below D1's
five-failure threshold, and seven total lobby creates remain below D6's
ten-create threshold. However, D4's following full game flow overlapped D3b's
second session. D3b correctly returned one row at 11:45 EDT; this contaminated
batch is excluded from its negative acceptance. D3b requires an isolated rerun
after that history leaves its ten-minute lookback. Its internal eleven-second
wait alone does not isolate it from later cases. This batch is also not a D3a
negative scenario: multiple successful endpoints may legitimately trigger D3a.

Scheduled-run evidence includes search name, SID, scheduled/dispatch epochs,
status, result count and notification action list. A scheduler success with
zero rows before case traffic is a baseline, not a malicious/benign coverage
result. A local Triggered Alerts REST query confirmed one D3b record following the
contaminated batch; this establishes tracking, not a successful negative test.
The runtime case and alert-record results are recorded below.

## Results

| Detection | Pinned benign / malicious rows | Scheduled benign (EDT) | Scheduled malicious (EDT) | Local record |
|---|---|---|---|---|
| D1 | 0 / 1 | 11:45: 0 | 11:50: 1 | SID matched |
| D2 | 0 / 1 | 11:45: 0 | 11:50: 1 | SID matched |
| D3a | 0 / 1 | 11:40: 0 | 11:50: 1 | SID matched |
| D3b | 0 / 1 | 11:55: 0 | 12:00: 1 | SID matched |
| D4 | 0 / 1 | 11:45: 0 | 11:50: 1 | SID matched |
| D5 | 0 / 1 | 11:45: 0 | 11:50: 1 | SID matched |
| D6 | 0 / 1 | 11:42: 0 | 11:49: 1 | SID matched |

All seven malicious cases returned one row and all seven benign cases returned
zero in endpoint- and time-scoped live searches. Fifteen query records include
the initial D3b negative and its isolated rerun. The 11:55 D3b scheduled rerun
returned zero; the separate positive returned one at 12:00, with a matching
local alert SID. Every recorded C09 scheduler execution completed successfully;
no failed/skipped records were returned. The deployment reload explains the
missing 11:38 D6 slot; this is not a claim of continuous uptime during deployment.

The scheduler runs the unchanged production searches against their full
lookbacks. Some benign and malicious generators share a source/account and
run in compatible batches; scheduled rows therefore represent the full window,
not a claim that only one case ran in every dispatch. Individual queries add
time bounds and case endpoint selectors for isolation, without changing the
production detection operators. Endpoints were derived from ordered observed
HELLO records and each existing generator's socket count, with unique endpoints,
complete HELLO coverage, matching telemetry signatures and ±0.3-second wall/server
time bounds asserted. D4's direct join is the unique game endpoint with no
master HELLO. This is derived attribution, not an embedded event run ID.
`case-signatures.json`, `enrich.py` and `queries.json` preserve the derivation
and exact scoped queries so a reviewer can assess that limitation.

The time-only D3b batch query and scheduled runs at 11:45 and 11:50 returned
the same overlap once each; these remain in evidence as contamination and
repeated-window behavior, not benign passes. The endpoint-scoped original
D3b case itself returned zero, and the isolated rerun independently established
a silent full scheduled window before the positive run.

Fresh ingestion was measured with `_indextime - _time`: -0.738 to
2.013 seconds across the observed events. `_indextime` is integral seconds, so
small negative values do not establish negative latency. Raw per-event-type
measurements and query text are in `queries.json`. This demonstrates the tested
pipeline timing, not an arbitrary-delay delivery guarantee. Test bursts stayed
inside the relevant fixed buckets (D1/D2 at 11:48 within 11:45–11:50, D3a at
11:48 within 11:40–11:50, D6 at 11:48:02 within 11:48–11:49). Cross-bucket burst
coverage remains the documented limitation; it was not redesigned here.

`btool check --app=c09_detections --debug` returned exit 1 because it also
reported three pre-existing C05 keys in the search app: alert_type,
alert_comparator and alert_threshold. No C09 invalid key was reported. The
check is not represented as globally clean; both backed-up search-app files
were byte-equal afterward.

Evidence: [acceptance mapping](evidence/c09-alerts-01/acceptance.json),
[effective settings and scheduler records](evidence/c09-alerts-01/runtime.json),
[local alert records](evidence/c09-alerts-01/alert-records.json),
[scoped queries](evidence/c09-alerts-01/queries.json),
[health and permissions](evidence/c09-alerts-01/health.json), and
[artifact hashes](evidence/c09-alerts-01/sha256.json).

Verification commands actually used include source ConfigParser comparisons,
`git diff --check`, the installed `btool savedsearches list --app=c09_detections
--debug`, `btool check --app=c09_detections --debug`, `systemctl is-active/show
Splunkd`, a Web login HTTP probe, the existing case functions from
`phase3/attack/cases.py`, CLI searches with saved case bounds/selectors, and
`| rest /servicesNS/-/c09_detections/alerts/fired_alerts/<search-name>`.
The evidence helpers and JSON preserve exact commands/searches and results.

An attempted bytecode compile of the temporary evidence helpers failed because
the system Python cache directory was not writable; a no-cache `compile()`
syntax check then passed. Shell SSH hostname resolution and Multipass socket
access were unavailable to the sandbox; authenticated VS Code terminals were
used. A malformed pasted SCP command failed and was rerun successfully. These
are tool/transfer limitations, not detector passes.

The instrumented master and game server remain running in dedicated VS Code
terminals. Their startup persistence was not changed; closing those terminals
or restarting the VMs can stop telemetry. Configuring service persistence is
outside this brief.

## Limits and rollback

The existing heuristic correlation, HMAC-generation assumptions, fixed-bucket
threshold behavior, D4 context truncation and overlapping D3b lookbacks remain.
Repeated D3b matches are possible without deduplication. Windows end at now;
late ingestion may miss an event. No change to SPL/windows/cadence is approved
in revision 1. A failed requirement requiring such a change blocks acceptance
and requires a revised brief.

Rollback disables the seven new schedules and restores the prior app state.
Because the app was absent, move it outside active apps while retaining evidence,
then reload/restart and check service health. Do not delete indexed data. Rollback
has not been exercised. Claude independent review, user acceptance and release
remain separate decisions.
