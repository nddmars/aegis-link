"""
vulnops — aegis-vulnops: Autonomous Vulnerability Lifecycle Management Agent.

Ingests findings from DefectDojo (REST API) or Excel/CSV files, verifies them
via SSH or Git repository access, proposes AI-generated remediation using Claude,
creates Jira/ServiceNow tickets from templates, and posts status updates back to
DefectDojo and Checkmarx.

Entry point:
    python -m vulnops.agent --source excel --file findings.xlsx
    python -m vulnops.agent --source defectdojo
"""

__version__ = "0.1.0"
__package_name__ = "aegis-vulnops"
