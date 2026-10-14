# Real-server attack traffic

Run from the Mac against the running lab servers:

```sh
python3 phase3/attack/run_all.py --master-ip 192.168.252.2 --game-ip 192.168.252.4
python3 phase3/attack/run_all.py --master-ip 192.168.252.2 --game-ip 192.168.252.4 --only d4_positive
```

Python standard library only. Each logical client gets a distinct source port and
uses the same socket for master and game traffic. Expected replies are validated;
timeouts or incorrect ACK results abort the run without recording a successful
window for that case. CREATE_LOBBY and G_STATE have no protocol reply. Full flows
check that their created lobby appears in LIST before JOIN. No retries are sent.
The game destination is the explicit `--game-ip`, with JOIN_ACK format checked.

`last_run.jsonl` is overwritten per invocation and contains only case, start, end,
and note. Stdout repeats these records and adds total elapsed time and timestamp
bounds. Server telemetry is emitted exclusively by the real servers.

Default `--gap 8` separates case traffic windows, but **does not isolate detection
lookback windows** (D1/D2: 5 min, D3a: 10 min, D6: 1 min). Validate each detection
against its case window and account for retained server sessions and prior events.
Game timeouts may occur after a case's end; include those later server events when
validating D3b lifetimes. D3b positive holds overlapping activity for about 3 s;
its sessions persist until the real server's 10 s idle timeout. D3b negative waits
11 s after its first session's final state before starting its second client.
D6 negative follows this brief's three creates spaced about 1 s apart; the schema
validation table instead describes a five-minute negative test. These generators
exercise traffic scenarios; they do not claim SPL or ingestion validation.

Repeated runs accumulate lobbies in the unmodified master. Its one-byte LIST count
cannot represent more than 255 lobbies; use a fresh lab server before reaching
that protocol limit. No generator resets or modifies server state files.
