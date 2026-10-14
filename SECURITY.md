# Security scope and public evidence

## Purpose and authorization

This portfolio lab demonstrates defensive protocol analysis, capture-driven
interoperability, privacy-conscious telemetry, and detection validation. Its UDP
protocols, intentionally weak authentication, and traffic generators are for
isolated systems the operator owns or is explicitly authorized to test.

The Phase 2 black boxes belong to this project. They were executed to collect
traffic, not opened, decompiled, or disassembled during the reversing exercise.
Their bytecode and answer key are not distributed. The public emulator and notes
describe observed behavior and distinguish tested findings from assumptions.

## Deliberate weaknesses and limitations

- Phase 1 credentials travel in cleartext; Phase 2 XOR is reversible obfuscation.
- The additive checksum is not cryptographic authentication or integrity.
- Access-control gaps and unbounded lobby growth are intentionally observable.
- Traffic generators send real requests and grow in-memory lobby state. Keep
  their destination inside the isolated lab; do not expose these services to
  the internet. Restart the lab server before exhausting its lobby-count field.
- D3b/D4 account correlation is heuristic, not proof of identity or compromise.
  Rate-based lobby detection is not proof of denial of service.
- Positive/negative lab scenario validation does not establish production
  accuracy. Splunk scheduling remains disabled pending the license and v3.1 work.

## Public artifacts and private material

The public captures are restricted to the three documented VM addresses and lab
UDP ports. They intentionally retain synthetic credentials, protocol session
values, private lab IP/MAC addresses, timestamps, and duplicate observations.
Capture metadata is stripped while packet content and timing remain intact.
Never reuse the published lab credentials for any real account.

`phase3/attack/last_run.jsonl` is a deliberate exception to the JSONL exclusion:
it contains only case names, UTC start/end windows, and descriptive notes. It is
not server telemetry and does not by itself prove detection validation.

Never commit HMAC keys, environment secrets, server JSONL, console logs, or new
unreviewed captures. Keep the runtime HMAC key outside the repository and log
folder. Ignore rules prevent accidental additions but do not remove tracked or
historical content. The clean-room server's debug output includes protocol
secrets and must not be ingested into Splunk without redaction.

Before publishing new evidence, review both current files and history with a
secret scanner, and inspect capture contents separately: text scanners cannot
certify packet payloads. If a real credential is found, revoke or rotate it
before removing historical copies.

## Reporting an unexpected exposure

Do not paste real credentials, private captures, or personal data into a public
issue. Report a minimal, redacted description through GitHub private vulnerability
reporting when enabled, or contact the repository owner privately first.
