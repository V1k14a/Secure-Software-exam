# CRA Dependency Sentinel 🛡️

**Agramkow Security Integration Project** *Automated Supply Chain Security & Regulatory Compliance*

## 📌 Project Overview
The **CRA Dependency Sentinel** is a specialized security orchestration tool designed to bridge the gap between automated vulnerability scanning and European regulatory requirements (**Cyber Resilience Act**).

It automates the generation of Software Bill of Materials (SBOM), identifies vulnerabilities in the software supply chain, and enforces Service Level Agreements (SLA) for remediation.

## 🚀 Key Features
- **Automated SBOM Generation**: Leverages `Syft` to create comprehensive CycloneDX/JSON inventory of all project dependencies.
- **Vulnerability Auditing**: Integrates with `Grype` to map dependencies against known CVE databases.
- **CRA Risk Engine**: A custom logic layer that evaluates compliance based on:
    - **Severity**: Immediate flags for Critical/High risks.
    - **Fix Availability**: Enforcement of remediation if a patch exists.
    - **SLA Aging**: Mandatory failure if Critical vulnerabilities remain unpatched for >48 hours.
- **Auditable Evidence**: Automatically generates a `CRA_Compliance_Report.md` and a centralized audit log for regulatory review.

## 🛠️ Technology Stack
- **Runtime**: .NET 9.0
- **Architecture**: Layered (Domain/Infrastructure/Main) using Dependency Injection.
- **Scanning Engine**: Anchore Syft & Grype (WinGet Managed).
- **Reporting**: Markdown & CSV.

## 📂 Project Structure
* **System.Domain**: Core business logic, Risk Evaluator, and Vulnerability Models.
* **System.Infrastructure**: Implementation of external tool runners (Syft/Grype).
* **System.Main**: CLI Entry point and Orchestration logic.

## 🚦 Getting Started

### Prerequisites
Ensure you have the following installed via WinGet:
```powershell
winget install Anchore.Syft
winget install Anchore.Grype