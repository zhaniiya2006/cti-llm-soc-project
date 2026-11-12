# Assignment 4 review against syllabus section 3.3

Reviewed baseline: GitHub main `12f2a62` (27 October 2026). Only the supplied syllabus and assignment descriptions were available; LMS-specific additional rubrics were not accessible through the public links.

| Requirement | What existed | Review result and completion |
|---|---|---|
| Week 6: study one ATT&CK technique | Detailed PowerShell report linked to Week 5 | Substantive basis present; condensed into evidence-based mapping |
| Week 6: simulate activity and map results | Archived Week 5 benign launches and results | Reuse explicitly identified; mapping does not claim maliciousness |
| Navigator supporting artifact | Report named a layer that was absent | Actual layer added; highlighting means study scope, not numerical coverage |
| Week 7: select CAR analytic | CAR-2014-04-003 selected | Choice retained; original executable/parent condition verified against MITRE |
| Week 7: implement in SIEM | Proposed methodology and future test plan | Previously incomplete. New native process observations, actual Elastic queries and full responses added |
| Week 7: ATT&CK mapping | T1059.001 discussed | Retained with evidence boundaries |
| Weekly transparency | Existing dated commits | Preserved. New commits use actual current dates; no retroactive weekly-work claim |
| Defense in 7-8 minutes | No dedicated guide | Added a timed defense outline; actual group defense remains the students' responsibility |

The original Week 6 report mentioned a CSV mapping without an actual linked file and referred to a Navigator path that did not exist. The revision uses a concrete in-report evidence table and supplies the JSON layer. The original Week 7 report correctly warned that Event 400 lacks parent context, but a plan alone did not meet the implementation requirement.

The new Week 7 collector uses native process snapshots from controlled launches. This adaptation preserves the CAR predicate but is less complete than continuous process-create telemetry. There is no native explorer-parent negative control; that branch is exercised only by clearly labelled synthetic boundary fixtures. Results are not production detection metrics.

This is a coverage review, not a teacher-assigned grade or a guarantee of acceptance. The syllabus also describes conditions on AI use and attribution. The group should review, understand and reproduce the work, and follow the instructor's applicable disclosure requirements before submission.
