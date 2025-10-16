# Dual-Domain APT Dataset Labeling Pipeline

A comprehensive 9-step pipeline for labeling cybersecurity datasets combining Sysmon (host-level) and NetFlow (network-level) events for Advanced Persistent Threat (APT) attack analysis.

## Repository Structure

```
scripts/
├── pipeline/        # 9-step production pipeline with documentation
├── exploratory/     # Analysis and labeling scripts
├── batch/           # Batch processing utilities
└── config/          # Configuration files
```

## Pipeline Steps

1. Elasticsearch data extraction
2. Sysmon CSV creation
3. NetFlow CSV creation  
4. Temporal causation correlation
5. Comprehensive correlation analysis
6. Seed event extraction (human-in-the-loop)
7. Attack lifecycle tracing
8. Labeled Sysmon dataset creation
9. Labeled NetFlow dataset creation

## Documentation

Complete documentation available in `scripts/pipeline/PIPELINE_OVERVIEW.md`

## Research Purpose

This repository supports academic research on dual-domain cybersecurity dataset labeling techniques and APT attack detection methodologies.
Updated Thu Oct 16 11:29:39 AM KST 2025
