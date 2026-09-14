# Analysis script for the transactional-consistency concurrent-traffic
# experiment (Section: transactional consistency). Parses decision_event
# perf-event captures (bpftool map event_pipe output) and verifies that
# every packet's (far_id, qer_id) decision matches exactly one validly
# configured pair for its generation -- never a torn/mixed combination.
import sys
from collections import Counter

def parse(path):
    events = []
    with open(path) as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith('=='):
            hex1 = lines[i+1].strip().replace(' ', '')
            hex2 = lines[i+2].strip().replace(' ', '') if i+2 < len(lines) else ''
            raw = bytes.fromhex(hex1 + hex2)[:16]
            far_id, qer_id, generation, pdr_id = (
                int.from_bytes(raw[0:4], 'little'), int.from_bytes(raw[4:8], 'little'),
                int.from_bytes(raw[8:12], 'little'), int.from_bytes(raw[12:16], 'little'))
            events.append((far_id, qer_id, generation, pdr_id))
            i += 3
        else:
            i += 1
    return events

if __name__ == '__main__':
    events = parse(sys.argv[1] if len(sys.argv) > 1 else 'decision_events_raw.txt')
    print('total events parsed:', len(events))
    valid_pairs = {(1, 1), (3, 3)}
    torn = [e for e in events if (e[0], e[1]) not in valid_pairs]
    print('torn (invalid far/qer pair) events:', len(torn))
    mismatches = sum(1 for far_id, qer_id, gen, pdr_id in events
                      if (far_id, qer_id) != ((1, 1) if gen % 2 == 0 else (3, 3)))
    print('generation-parity mismatches:', mismatches)
    print('pair distribution:', Counter((e[0], e[1]) for e in events))
    print('distinct generations observed:', len(set(e[2] for e in events)))
