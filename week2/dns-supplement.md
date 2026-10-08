# Week 2 supplement — verified DNS relationships

The previous Maltego screenshot demonstrates five manually entered nodes and zero links. To prepare a graph backed by actual data, [collect_dns.py](collect_dns.py) queried the reserved training domain `example.com` through [Google's documented DNS-over-HTTPS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json).

The collection was performed on **9 October 2026, approximately 00:00 Asia/Qyzylorda**, corresponding to 8 October 2026, approximately 19:00 UTC. Exact observation timestamps, query URLs, DNSSEC AD flags and raw-response hashes are in [the manifest](data/dns/collection-manifest.json).

| Relation | Observed target | Evidence |
|---|---|---|
| A | `104.20.23.154` | [Raw response](data/dns/example-com-a.json) |
| A | `172.66.147.243` | Same response |
| NS | `hera.ns.cloudflare.com` | [Raw response](data/dns/example-com-ns.json) |
| NS | `elliott.ns.cloudflare.com` | Same response |
| AAAA | `2606:4700:10::6814:179a` | [Raw response](data/dns/example-com-aaaa.json) |
| AAAA | `2606:4700:10::ac42:93f3` | Same response |

[The MX response](data/dns/example-com-mx.json) contains null MX `0 .`. It is not represented as a mail-server node. DNS answers and shared providers do not establish exclusive infrastructure ownership or maliciousness.

[relationships.csv](data/dns/relationships.csv) preserves six source → relation → target rows with record type, TTL, observation time and evidence filename. These are actual DNS-derived relationships; they have not yet been executed as transforms in the Maltego client. A graph imported from this CSV must be labelled an import of independently collected data.

## Finish the Maltego evidence

1. Open Maltego Graph and sign in to the configured account.
2. Create a new graph with only the Domain entity `example.com`.
3. Run the available standard DNS transforms for name servers and IP addresses. Preserve the transform names and execution output. Results may change after the recorded observation time.
4. Inspect each relationship and export the graph together with a full interface screenshot showing readable labels and links.
5. Compare the observed results with the DNS snapshot, documenting differences rather than inserting unverified nodes.

The [official Maltego infrastructure guide](https://www.maltego.com/blog/how-to-use-maltego-transforms-to-map-network-infrastructure-an-in-depth-guide/) explains the DNS-entity-to-IP workflow. The [installation documentation](https://docs.maltego.com/en/support/solutions/articles/15000008704-installing-maltego) covers client setup.

Recollect into a new directory to preserve the present snapshot:

```powershell
python week2/collect_dns.py --output-dir week2/data/dns-new-run
```

**Current evidence boundary:** verified DNS collection is complete. The new Maltego client transform execution and screenshot remain pending until the client is ready and authenticated. The old screenshot is preserved as historical evidence.
