#!/usr/bin/env python3
"""Run real-server scenarios and record only their UTC validation windows."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import time

try:
    from .cases import CASES
except ImportError:
    from cases import CASES


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError('expected an IPv4 address') from exc


def gap_seconds(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError('gap must be finite and nonnegative')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master-ip', required=True, type=ipv4)
    parser.add_argument('--game-ip', required=True, type=ipv4)
    parser.add_argument('--only', choices=[fn.__name__ for fn, _ in CASES])
    parser.add_argument('--gap', type=gap_seconds, default=8)
    args = parser.parse_args()
    selected = [(fn, note) for fn, note in CASES if not args.only or fn.__name__ == args.only]
    began = time.monotonic()
    earliest = latest = None
    with Path(__file__).with_name('last_run.jsonl').open('w', encoding='utf-8') as log:
        for index, (fn, note) in enumerate(selected):
            start = utc_now()
            fn(args.master_ip, args.game_ip)  # Fail fast if an expected reply is absent/wrong.
            end = utc_now()
            record = {'case': fn.__name__, 'start': start, 'end': end, 'note': note}
            line = json.dumps(record)
            log.write(line + '\n')
            log.flush()
            print(line, flush=True)
            earliest = earliest or start
            latest = end
            if index < len(selected) - 1:
                time.sleep(args.gap)
    print(f'total_wall_clock_s={time.monotonic() - began:.3f} earliest={earliest} latest={latest}', flush=True)


if __name__ == '__main__':
    main()
