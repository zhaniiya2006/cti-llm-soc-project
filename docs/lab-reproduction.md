# Local lab reproduction - Weeks 7 and 9

The completed 12 November 2026 run used Windows, PowerShell 7, Windows PowerShell 5.1, Python 3.12 from the available runtime, Elasticsearch 9.5.6 and Kibana 9.5.6. The old Docker lab was not installed on this host, so a separate portable lab was prepared under the working directory. Its binaries and indexes are not committed to GitHub.

## Runtime

Download the Windows ZIP packages from the official [Elasticsearch](https://www.elastic.co/downloads/elasticsearch) and [Kibana](https://www.elastic.co/downloads/kibana) pages and verify their vendor SHA-512 files. See [Elastic's Windows ZIP instructions](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-with-zip-on-windows).

For this disposable, single-host training lab, Elasticsearch used:

```yaml
cluster.name: cti-course-lab
node.name: cti-local-node
network.host: 127.0.0.1
http.port: 19200
transport.port: 19300
discovery.type: single-node
xpack.security.enabled: false
xpack.ml.enabled: false
xpack.watcher.enabled: false
```

The new local lab has no authentication and is bound only to loopback. This is not a production configuration. It does not change authentication or audit policy in an existing service. A network-accessible deployment requires an appropriately secured configuration.

The small experiment used a 384 MiB Elasticsearch JVM heap, configured in `config/jvm.options.d/course.options`. Kibana needs a larger Node heap for startup; the initial 512 MiB attempt exhausted memory and was restarted with 1536 MiB. This hardware/runtime issue did not change the input data or search predicates.

Kibana configuration:

```yaml
server.host: 127.0.0.1
server.port: 15601
elasticsearch.hosts: ["http://127.0.0.1:19200"]
telemetry.enabled: false
xpack.fleet.enabled: false
```

Start the vendor launch scripts from their extracted directories. No Windows service installation is needed. Verify the Elastic root/version API and Kibana status before executing UI queries. Ports differ from the old Week 5 lab to avoid collisions.

## Fresh data and query replay

Run from the repository root. The collector requires Windows and PowerShell 7, launches only the documented benign test processes, and exports only the known child PIDs. It fails rather than fabricating a missing observation. The shell-association batch executor uses Windows PowerShell/CMD behavior; inspect the saved inputs before running.

```powershell
./tools/collect_training.ps1 -Mode car -OutputDirectory ../new-car-data
python tools/run_training_analytics.py car --data ../new-car-data/process-observations.jsonl --output ../new-car-results
./tools/collect_training.ps1 -Mode atomic -OutputDirectory ../new-atomic-data
python tools/run_training_analytics.py atomic --data ../new-atomic-data/process-observations.jsonl --output ../new-atomic-results
```

The JSON dataset may also be replayed directly from its archived path into a new index without executing the commands again. Label that operation as a replay. Each evidence output folder must be empty/new; original exports remain protected.

Open `http://127.0.0.1:15601/app/dev_tools#/console` and use the saved `kibana-console.txt` for the relevant week. The archived datasets are tiny and benign. Scope query output to necessary fields when taking screenshots, while preserving complete responses in the API transcript.

After review, stop the exact lab processes launched from the extracted lab directory. Keep the repository evidence; any replay data/index cleanup should target only the run-specific paths and index names.

## Interpretation

This is Elastic-based log analysis with explicit direct ingestion and searches. It is not a deployed Elastic Agent fleet, an alerting service or a full LLM application. Native CIM snapshots are actual observations of controlled processes, but they are not Sysmon/4688 records and can miss short-lived activity. Event 400 corroboration does not replace parent or network telemetry.
