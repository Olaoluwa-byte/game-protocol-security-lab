# C09 detection app

Copy this `c09_detections` directory onto the Splunk host under
`/opt/splunk/etc/apps/`, then restart Splunk using the deployment's normal service
procedure. The searches expect index `c09` and the fields in
[telemetry schema v1.0](../../docs/telemetry-schema.md). No forwarder settings are
included. `metadata/default.meta` exports the app's knowledge objects system-wide,
with read access for all roles and write access for admins.

Every search explicitly has **`enableSched = 0`**. Scheduling is intentionally
disabled pending activation of the Developer license. The `cron_schedule` values
are future intent only, as stated in the leading comments; this package does not
enable them or configure outbound alert actions. Search windows end at `now`:
D1/D2/D4/D5 use five minutes, D3a/D3b ten minutes, and D6 one minute.

D3b carries `user_ref` from successful auth onto endpoint game events and counts
live sessions per account using joins and timeouts. The corrected form was
validated by the lab operator on 2026-10-14 against saved isolated case windows:
positive fired (`live_sessions=2`), negative silent. Correlation remains heuristic;
see [detections/README.md](../../detections/README.md) for limitations.

Packaging checks were local visual and balanced-delimiter checks, plus config
inspection; no live Splunk queries, installation, restart, or `btool` run occurred.
Splunk's [savedsearches.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.3-configuration-file-reference/savedsearches.conf)
defines `enableSched`, dispatch windows, cron intent, and severity settings.
