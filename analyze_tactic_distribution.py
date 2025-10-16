#!/usr/bin/env python3
"""
Analyze tactic distribution across all labeled Sysmon and NetFlow datasets
"""

import pandas as pd
import glob
from pathlib import Path
from collections import defaultdict

def analyze_dataset(filepath, dataset_type):
    """Analyze a single labeled CSV file and return tactic counts"""
    try:
        # Read CSV
        df = pd.read_csv(filepath)

        # Get APT type and run ID from filepath
        parts = Path(filepath).parts
        apt_type = parts[-2].split('-')[0] + '-' + parts[-2].split('-')[1]  # e.g., apt-1
        run_id = parts[-2].split('-')[-1]  # e.g., run-04

        # Count total events
        total_events = len(df)

        # Count malicious events
        if 'Label' in df.columns:
            malicious_events = len(df[df['Label'] == 'malicious'])
            benign_events = len(df[df['Label'] == 'benign'])
        else:
            malicious_events = 0
            benign_events = total_events

        # Count events per tactic (only for malicious events)
        tactic_counts = {}
        if 'Tactic' in df.columns:
            malicious_df = df[df['Label'] == 'malicious'] if 'Label' in df.columns else df
            tactic_series = malicious_df['Tactic'].fillna('None').value_counts()
            tactic_counts = tactic_series.to_dict()
            # Remove None/null entries
            tactic_counts = {k: v for k, v in tactic_counts.items() if k not in ['None', 'nan', '']}

        return {
            'apt_type': apt_type,
            'run_id': run_id,
            'dataset_type': dataset_type,
            'total_events': total_events,
            'benign_events': benign_events,
            'malicious_events': malicious_events,
            'tactic_counts': tactic_counts,
            'filepath': filepath
        }
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return None

def main():
    # Find all labeled datasets
    sysmon_files = sorted(glob.glob('dataset/*/apt-*-run-*/sysmon-run-*-labeled.csv'))
    netflow_files = sorted(glob.glob('dataset/*/apt-*-run-*/netflow-run-*-labeled.csv'))

    print(f"Found {len(sysmon_files)} Sysmon datasets")
    print(f"Found {len(netflow_files)} NetFlow datasets")
    print()

    # Analyze all datasets
    results = []

    print("Analyzing Sysmon datasets...")
    for filepath in sysmon_files:
        result = analyze_dataset(filepath, 'Sysmon')
        if result:
            results.append(result)

    print("Analyzing NetFlow datasets...")
    for filepath in netflow_files:
        result = analyze_dataset(filepath, 'NetFlow')
        if result:
            results.append(result)

    # Aggregate statistics
    print("\n" + "="*100)
    print("TACTIC DISTRIBUTION ANALYSIS")
    print("="*100)

    # Group by APT type and dataset type
    apt_types = sorted(set([r['apt_type'] for r in results]))

    # Collect all unique tactics
    all_tactics = set()
    for r in results:
        all_tactics.update(r['tactic_counts'].keys())
    all_tactics = sorted(all_tactics)

    # Create summary tables
    for dataset_type in ['Sysmon', 'NetFlow']:
        print(f"\n{'#'*100}")
        print(f"# {dataset_type.upper()} DATASETS - TACTIC DISTRIBUTION")
        print(f"{'#'*100}\n")

        # Header
        print(f"{'APT-Run':<15} {'Total':<10} {'Benign':<10} {'Malicious':<12}", end='')
        for tactic in all_tactics:
            print(f"{tactic:<18}", end='')
        print()
        print("-" * (45 + len(all_tactics) * 18))

        # Data rows
        dataset_results = [r for r in results if r['dataset_type'] == dataset_type]

        for r in sorted(dataset_results, key=lambda x: (x['apt_type'], x['run_id'])):
            run_label = f"{r['apt_type']}-{r['run_id']}"
            print(f"{run_label:<15} {r['total_events']:<10} {r['benign_events']:<10} {r['malicious_events']:<12}", end='')

            for tactic in all_tactics:
                count = r['tactic_counts'].get(tactic, 0)
                print(f"{count:<18}", end='')
            print()

        # Summary statistics per APT type
        print("\n" + "-" * (45 + len(all_tactics) * 18))
        print("SUMMARY BY APT TYPE:")
        print("-" * (45 + len(all_tactics) * 18))

        for apt_type in apt_types:
            apt_results = [r for r in dataset_results if r['apt_type'] == apt_type]
            if not apt_results:
                continue

            total_events = sum(r['total_events'] for r in apt_results)
            total_benign = sum(r['benign_events'] for r in apt_results)
            total_malicious = sum(r['malicious_events'] for r in apt_results)

            print(f"{apt_type:<15} {total_events:<10} {total_benign:<10} {total_malicious:<12}", end='')

            for tactic in all_tactics:
                tactic_sum = sum(r['tactic_counts'].get(tactic, 0) for r in apt_results)
                print(f"{tactic_sum:<18}", end='')
            print()

        # Grand total
        print("-" * (45 + len(all_tactics) * 18))
        total_all = sum(r['total_events'] for r in dataset_results)
        benign_all = sum(r['benign_events'] for r in dataset_results)
        malicious_all = sum(r['malicious_events'] for r in dataset_results)

        print(f"{'TOTAL':<15} {total_all:<10} {benign_all:<10} {malicious_all:<12}", end='')
        for tactic in all_tactics:
            tactic_total = sum(r['tactic_counts'].get(tactic, 0) for r in dataset_results)
            print(f"{tactic_total:<18}", end='')
        print()

    print("\n" + "="*100)
    print("Analysis complete!")
    print("="*100)

if __name__ == "__main__":
    main()
