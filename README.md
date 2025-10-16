# FullAPT2025: Dual-Domain APT Attack Dataset

Dataset: [Link](https://zenodo.org/records/17363885)

This repository presents the documentation related to the production of FullAPT2025, the ultimate cybersecurity dataset based on data collection of emulated APT attacks.

FullAPT2025 features:
- 06 APT attacks.
- Total of 54 different TTPs (Tactics, Techniques, and Procedures).
- Dataset containing Host events (based on Sysmon events) and network events (based on network flows). In this way, we believe we capture attack patterns in both domains: host-domain and network-domain.

The objective of this repository is to provide documentation for understanding:

- How this dataset was generated?
- How this dataset was labeled?

<!-- A comprehensive 9-step pipeline for labeling cybersecurity datasets combining Sysmon (host-level) and NetFlow (network-level) events for Advanced Persistent Threat (APT) attack analysis. -->

![Figure 1. Dataset Generation Methodology](images/methodology_png.png)
**Figure 1**: Dataset Generation Methodology consists of three phases. Phase 1 is the APT attack emulation over a virtual network. Phase 2 is the raw dataset generation. And, Phase 3 involves the proceessing to create the labeled datasets.



## Repository Structure

```
attack-emulation/    # details on how the APT attacks were emulated
├── virtual-network/        # how it virtual network was built
└── apt-attacks/            # how apt attacks were emulated
scripts/
├── pipeline/        # 9-step production pipeline with documentation
├── exploratory/     # (currently not available)
├── batch/           # (currently not available)
└── config/          # (currently not available)
```

<!-- ## Pipeline Steps

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

Complete documentation available in `scripts/pipeline/PIPELINE_OVERVIEW.md` -->

## Research Purpose

This repository supports academic research on dual-domain cybersecurity dataset labeling techniques and APT attack detection methodologies.
Updated Thu Oct 16 11:29:39 AM KST 2025
