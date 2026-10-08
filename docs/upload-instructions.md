# Uploading the corrected project to GitHub

Repository: [zhaniiya2006/cti-llm-soc-project](https://github.com/zhaniiya2006/cti-llm-soc-project).

## Folder structure

Extract the final ZIP. Its root must contain `README.md`, `Week1`, `week2`, `week3`, `week4`, `docs`, `tests` and `tools`. The Week 3 report belongs at `week3/week3-report.md`; its data belongs in `week3/data`, figures in `week3/images` and the rule in `week3/sigma`.

## Preferred: apply the prepared Git branch

Review the changes on `codex/audit-weeks1-4` and merge its pull request when one is available. This preserves the intended file moves and removes misplaced root copies.

## Browser upload if Git access is unavailable

1. Open the repository's **Code** tab and select the intended branch.
2. Choose **Add file -> Upload files** at the repository root.
3. Drag the extracted folders and root files together from File Explorer. Keep the folders intact; uploading the contents of `week3` at the repository root breaks relative paths.
4. Commit with a message such as `Fix week structure and add audited evidence`.
5. Remove the old misplaced root copies after the corrected versions exist: `week3-report.md`, `process_iocs.py`, `render_evidence.py`, `raw_iocs.csv`, `normalized_iocs.csv`, `misp-event.json`, `processing-summary.json`, `example_domain_connection.yml`, `01-processing-results.png`, `02-misp-import-payload.png`. These are duplicated Week 3 files, not root project files.
6. Open the root README, each weekly report, the three Week 3 images and the data links on GitHub. Confirm they render and open. The old nested `week2/week2/images` copies can be removed once `week2/images` is present.

Do not treat uploading the archive itself as installing the directory structure in the repository. GitHub displays individual report and evidence files when the extracted folders are uploaded.
