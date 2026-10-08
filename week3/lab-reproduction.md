# Week 3 lab reproduction and evidence

## What was verified

The exercise used an existing local Docker MISP lab, not a fresh installation performed by the processing script. During the audit, `docker ps` showed core, database, Redis, modules and nginx containers running. The core image was `ghcr.io/misp/misp-docker/misp-core:latest`; the interface displayed MISP 2.5.47. The current image tag is mutable, so it is not presented as a permanently reproducible version pin.

The lab was accessible at `http://localhost:8080`, with host bindings restricted to `127.0.0.1:8080` and `127.0.0.1:8443`. Event 1 was imported from the generated JSON. [The actual interface screenshot](images/03-misp-event-live.jpg) shows four attributes, `Published: No`, organization-only distribution and unchecked IDS flags.

The [lab status snapshot](data/misp-lab-status.json) records container status, image names and bindings without passwords or environment variables. It is a snapshot, not a bundled running MISP server. Local accounts and the database are not included in the academic project.

## Reproduce the processing

From the repository root, with Python 3.10 or newer:

```powershell
python week3/process_iocs.py
python week3/enrich_correlate.py
python -m unittest discover -s tests -v
python tools/verify_repo.py
```

The default input is `week3/data/raw_iocs.csv`. An alternative input and output directory can be selected with `--input` and `--output-dir`; `--event-date` accepts an ISO date. Without an explicit date, the event uses the latest accepted observation date, so rerunning the included sample does not change it to today's date.

The normalization subset is deliberately limited to ASCII domains, IPv4 destination addresses, domain-host HTTP(S) URLs without credentials and SHA-256 values. IPv6, IP-host URLs and internationalized domains require an extended implementation and are not claimed here. Confidence and first-seen timestamps in the raw sample are synthetic exercise metadata, not measured reliability or incident times.

## Deploy your own MISP lab

Use the official [MISP Docker repository](https://github.com/MISP/misp-docker) and its current instructions. Clone it into a separate lab directory, copy `template.env` to `.env`, configure the local account and database credentials, and run `docker compose pull` followed by `docker compose up -d`. Check health and the configured listening address before import. For an isolated course lab, bind published ports to loopback in the Compose configuration. The upstream instructions determine exact service names and options for the selected revision.

This repository does not include the lab's credentials. Use the account configured for your installation; do not assume its password matches an upstream default.

## Import and inspect the event

1. Open the local MISP instance and sign in with the configured lab account.
2. Use the event import interface and select **MISP standard JSON**.
3. Upload `week3/data/misp-event.json`. Import once into a fresh lab; do not create duplicates just to obtain another success screenshot.
4. Open the created event. Its numeric ID can differ between installations.
5. Check the domain, IPv4, URL and SHA-256 values against `normalized_iocs.csv`, verify four attributes, `Published: No`, organization-only distribution and all `to_ids=false`.
6. Save a real screenshot into `week3/images` if documenting your own reproduction.

## Training reading notes

The relevant parts of the official [MISP user training](https://www.misp-project.org/misp-training/1-misp-usage.pdf) were reviewed during the audit: the Event View section (PDF page 14) distinguishes type/category, IDS and correlations; the event creation section (page 15) lists import methods; the distribution section (page 20) includes Your Organisation Only. These notes support the import checks above. They do not claim a full training-course completion.

## Additional tools

`enrich_correlate.py` attaches cited documentation context, recalculates the empty-file hash and relates the URL record to its exact hostname record. This is local enrichment and syntactic correlation, not a multi-event MISP correlation or reputation query.

Install `requirements-validation.txt` with Python 3.11 or newer for pySigma 2.0.0, then run `python tools/validate_sigma.py`. The saved result confirms parsing only. Elastic was not deployed or queried in this exercise; it is a lecture tool in the syllabus rather than a separately stated Week 3 practical task.
