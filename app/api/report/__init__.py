"""The downloadable PDF security assessment.

pdf.py turns one saved Analysis (plus an already cached fix-impact result and
any cached scenarios) into a render context and then into PDF bytes.
router.py serves it at GET /api/analyses/{id}/report.pdf.

WeasyPrint is imported only when a report is rendered or probed, so the API and
its OpenAPI export work on a machine without Pango.
"""
