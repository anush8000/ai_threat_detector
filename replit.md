# AI-Powered Threat Detection System

## Overview
Upgraded CSPM dashboard with CWPP simulation, Risk Scoring, and Drift Detection.

## New Modules
- `utils/riskScore.ts`: Implements severity/exposure-based risk calculation.
- `utils/threatCategory.ts`: Categorizes issues (Data Exposure, Network Exposure, etc.).
- `utils/driftDetection.ts`: Compares scans to identify new/resolved issues.
- `services/runtimeMonitor.ts`: Simulates CWPP runtime anomalies (CPU spikes, suspicious ports).

## UI Enhancements
- **Threat Risk Overview**: New panel for high-level security metrics.
- **CSPM Configuration Threat Detection**: Renamed and enhanced with risk scores and categories.
- **CWPP Runtime Threat Detection**: New live-style monitoring section for simulated instance health.
- **Configuration Drift**: Real-time tracking of security state changes.

## Integration
The `Dashboard.tsx` now imports these utilities to enrich the data fetched from Steampipe (or mock data) before rendering. Existing functionality remains intact, with new data points added safely to the `SecurityIssue` interface.
