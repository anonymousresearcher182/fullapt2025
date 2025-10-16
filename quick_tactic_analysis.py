#!/usr/bin/env python3
"""
Quick tactic distribution analysis - optimized for large CSV files
"""

import pandas as pd
import glob
from pathlib import Path

def quick_analyze(filepath, dataset_type):
    """Quick analysis reading only Label and Tactic columns"""
    try:
        parts = Path(filepath).parts
        apt_type = parts[-2].split('-')[0] + '-' + parts[-2].split('-')[1]
        run_id = parts[-2].split('-')[-1]

        # Only read Label and Tactic columns
        df = pd.read_csv(filepath, usecols=['Label', 'Tactic'], low_memory=False)

        total = len(df)
        malicious = (df['Label'] == 'malicious').sum()
        benign = total - malicious

        # Count tactics for malicious events only
        mal_df = df[df['Label'] == 'malicious']
        tactic_counts = mal_df['Tactic'].value_counts().to_dict()

        # Remove None/null
        tactic_counts = {str(k): v for k, v in tactic_counts.items() if pd.notna(k) and str(k) != 'nan'}

        return apt_type, run_id, dataset_type, total, benign, malicious, tactic_counts
    except Exception as e:
        print(f"Error with {filepath}: {e}")
        return None

# Find files
sysmon_files = sorted(glob.glob('dataset/*/apt-*-run-*/sysmon-run-*-labeled.csv'))
netflow_files = sorted(glob.glob('dataset/*/apt-*-run-*/netflow-run-*-labeled.csv'))

print(f"Processing {len(sysmon_files)} Sysmon + {len(netflow_files)} NetFlow datasets...\n")

# Process all
results = []

for f in sysmon_files:
    r = quick_analyze(f, 'Sysmon')
    if r: results.append(r)

for f in netflow_files:
    r = quick_analyze(f, 'NetFlow')
    if r: results.append(r)

# Get all tactics
all_tactics = set()
for r in results:
    all_tactics.update(r[6].keys())
all_tactics = sorted(all_tactics)

# Print results
for dataset_type in ['Sysmon', 'NetFlow']:
    print(f"\n{'='*120}")
    print(f"{dataset_type.upper()} TACTIC DISTRIBUTION")
    print(f"{'='*120}\n")

    # Header
    print(f"{'Run':<12} {'Total':>10} {'Benign':>10} {'Malicious':>10}", end='  ')
    for t in all_tactics:
        print(f"{t[:15]:>16}", end='')
    print()
    print("-" * (42 + len(all_tactics) * 16))

    # Data
    data = [r for r in results if r[2] == dataset_type]
    apt_totals = {}

    for apt, run, dt, total, benign, mal, tcounts in sorted(data):
        print(f"{apt}-{run:<6} {total:>10} {benign:>10} {mal:>10}", end='  ')
        for t in all_tactics:
            print(f"{tcounts.get(t, 0):>16}", end='')
        print()

        # Accumulate APT totals
        if apt not in apt_totals:
            apt_totals[apt] = {'total': 0, 'benign': 0, 'malicious': 0, 'tactics': {}}
        apt_totals[apt]['total'] += total
        apt_totals[apt]['benign'] += benign
        apt_totals[apt]['malicious'] += mal
        for t, c in tcounts.items():
            apt_totals[apt]['tactics'][t] = apt_totals[apt]['tactics'].get(t, 0) + c

    # APT summaries
    print("-" * (42 + len(all_tactics) * 16))
    print("\nSUMMARY BY APT:")
    print("-" * (42 + len(all_tactics) * 16))

    for apt in sorted(apt_totals.keys()):
        at = apt_totals[apt]
        print(f"{apt:<12} {at['total']:>10} {at['benign']:>10} {at['malicious']:>10}", end='  ')
        for t in all_tactics:
            print(f"{at['tactics'].get(t, 0):>16}", end='')
        print()

    # Grand total
    print("-" * (42 + len(all_tactics) * 16))
    gt = sum(r[3] for r in data)
    gb = sum(r[4] for r in data)
    gm = sum(r[5] for r in data)
    print(f"{'TOTAL':<12} {gt:>10} {gb:>10} {gm:>10}", end='  ')
    for t in all_tactics:
        tc = sum(r[6].get(t, 0) for r in data)
        print(f"{tc:>16}", end='')
    print()

print(f"\n{'='*120}\n")
