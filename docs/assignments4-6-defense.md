# Defense outlines - target 7 minutes 30 seconds per assignment

Use actual group members for the roles below. Do not invent individual contributions. The repository is a review aid; the group must be able to explain and, where practical, replay the commands.

## Assignment 4: Weeks 6-7

| Time | Presenter role | Show and explain |
|---|---|---|
| 0:00-0:45 | Introduction | Project topic and why PowerShell follows Week 5 |
| 0:45-2:00 | ATT&CK analyst | Tactic/technique/procedure; four benign controls and 4/2/1 archived counts |
| 2:00-2:45 | ATT&CK analyst | Actual Navigator layer; blue is study scope, no coverage percentage |
| 2:45-4:00 | Lab operator | Why Event 400 could not supply the CAR parent; native CIM collection and its limits |
| 4:00-5:30 | Detection analyst | Actual query, index and 3 baseline / 2 CAR matches; missing-parent guard |
| 5:30-6:30 | Detection analyst | Benign verdicts and why automation parents can match |
| 6:30-7:30 | Reviewer | Evidence chain, native vs fixture checks, next telemetry improvement |

Likely questions: Why CAR instead of just -EncodedCommand? CAR tests parent context, so it asks a different behavioral question. Why no malware-detection claim? All controls are benign. Why snapshots? The available host lacked the prior sensor; snapshots supplied verified parent context for our controlled PIDs, with short-lived-process limitations disclosed.

## Assignment 5: Week 8

| Time | Presenter role | Show and explain |
|---|---|---|
| 0:00-0:45 | Introduction | Objective and disposable-VM scope |
| 0:45-2:15 | Planner | Walk through delivery -> execution -> task persistence |
| 2:15-3:45 | Planner | Dummy collection/archive -> loopback transfer; ATT&CK mapping |
| 3:45-5:00 | Collector owner | Required logs and acceptance criteria; absent telemetry stops the branch |
| 5:00-6:15 | Analyst | How to correlate evidence; local delivery/transfer realism limits |
| 6:15-7:30 | Reviewer | Cleanup and why each mechanism was selected |

Likely questions: Was the full chain executed? No; Week 8 requires a plan, and its table is labelled planned. Why loopback? It makes byte/hash checking possible without external transfer, but cannot validate enterprise exfiltration controls. Does task registration prove persistence? No; a trigger execution and cleanup check are also needed.

## Assignment 6: Weeks 9-10

| Time | Presenter role | Show and explain |
|---|---|---|
| 0:00-0:45 | Introduction | Two selected atomic GUIDs and why they fit the project |
| 0:45-2:00 | Lab operator | Pinned source, reviewed input overrides, actual exit/output/cleanup checks |
| 2:00-3:15 | Analyst | Elastic counts 2/1/1/1; -e gap in the older query |
| 3:15-4:15 | Analyst | Native observations and benign verdicts; exercise-specific batch search |
| 4:15-6:00 | CTI analyst | Historical APT29 source, six evidence-to-technique mappings |
| 6:00-7:30 | Reviewer | What our lab cannot detect; prioritized collection improvements |

Likely questions: Did Invoke-AtomicRedTeam run? No; reviewed commands from pinned official tests were executed directly with disclosed inputs. Did all defaults remain unchanged? No; harmless observation delays and isolated paths are recorded. Does PowerShell imply APT29? No; shared techniques do not establish actor identity. Were all campaign variants one chain? No; the mapping table preserves separate source locators.
