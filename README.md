# AI crawler log analyzer

Find requests from AI-related crawlers in server logs and see which URLs they requested, when they appeared, and which HTTP responses they received. The analyzer reads common Apache/nginx combined logs, IIS W3C logs, and selected JSON-lines fields, including Cloudflare Logpush fields. It also handles gzip files.

It generates a Markdown report and CSV breakdowns by date, URL, response status, and IP. An optional sitemap adds a basic coverage comparison.

## Try the fictional example

Requires Python 3.10 or newer. There are no third-party Python dependencies.

```bash
python analyze.py --logs sample.log --client Example --out demo-output --offline
```

The three requests and documentation-only IP addresses in [sample.log](sample.log) are fictional. See the [example report](example-report.md). `--offline` uses any existing cached ranges but does not fetch new ones; it also skips remote sitemap children.

For your own logs:

```bash
python analyze.py --logs /path/to/access.log --client Example --out reports
```

Use `--sitemap /path/to/sitemap.xml` for a local sitemap or provide a URL when online. By default, the tool may retrieve published OpenAI and Perplexity IP lists, caching them for seven days and falling back to an older cache if a fetch fails. `--refresh-ips` requests updated lists. Do not upload private server logs, output files containing IPs, cache files, or credentials to a public repository.

## How to interpret it

- User-agent strings can be spoofed. Where a supported vendor range list and a valid IP are available, the report separates current-list matches from addresses outside the list. It keeps missing IPs and requests without an available list as **unverified**.
- Range lists can change. A match or mismatch against the list available today does not establish who owned an IP at the time of an older request. A mismatch is not proof of malicious intent.
- Counts describe the logs provided. Origin logs may miss requests served or blocked by a CDN or WAF, and the tracked user-agent list is not exhaustive.
- A request does not prove a page was indexed, cited, shown in an answer, or used for training. Categories are broad indicators based on the registered user agent, not a record of every possible downstream use.
- `Google-Extended` is a robots.txt control token, not a separate request user agent. The analyzer cannot comprehensively attribute Google AI activity from access logs.

Crawler identities and verification rules can change. The OpenAI and Perplexity IP-list URLs are documented by their providers; Anthropic says it does not currently publish crawler ranges. See the [OpenAI crawler documentation](https://developers.openai.com/api/docs/bots), [Perplexity crawler documentation](https://docs.perplexity.ai/docs/resources/perplexity-crawlers), [Anthropic crawler guidance](https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler), and [Google crawler documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers).

## Tests

```bash
python -m unittest -v test_analyze
```

The tests exercise combined, W3C, JSON-lines and gzip input, IP match/mismatch/unknown handling, and the offline sitemap boundary. The online IP-list download path is dependent on provider availability and has not been integration-tested as part of this release.
