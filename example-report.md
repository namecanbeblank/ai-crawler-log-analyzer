# AI Crawler Report — Example

- **Log window:** 2026-11-01 to 2026-11-02
- **Files parsed:** 1  |  **Lines:** 3 (parsed 3, unparseable 0)
- **Requests matching tracked user agents:** 3 (100.0% of parsed traffic)
- **Generated:** 2026-11-10 by ai-crawler-logs

## Summary by bot

| Bot | Type | Hits | Days seen | IP-range matches | Unverified | Blocked (401/403/429) | robots.txt fetches |
|---|---|---:|---:|---:|---:|---:|---:|
| GPTBot | Training crawler | 1 | 1 | 0 | 1 | 0.0% | 0 |
| ClaudeBot | Training crawler | 1 | 1 | 0 | 1 | 0.0% | 0 |
| PerplexityBot | AI search indexer | 1 | 1 | 0 | 1 | 100.0% | 0 |

Requests outside the available IP ranges are excluded from this table. Unverified requests have no usable IP or no available range list and rely on the user agent. Range matches use the list available at analysis time, not necessarily at request time.

## What this means

- **Training crawlers** (2 hits): requests attributed to crawlers associated with training; requests alone do not prove content was used for training.
- **AI search indexers** (1 hits): requests attributed to AI search crawlers; a request does not establish indexing or citation.
- **User-triggered fetchers** (0 hits): requests attributed to fetchers triggered by users or site owners; logs alone do not establish a citation.

## Top pages per bot

### GPTBot (OpenAI — Training crawler)

- `/guides/example` — 1
- Status codes: 200: 1

### ClaudeBot (Anthropic — Training crawler)

- `/blog/sample` — 1
- Status codes: 200: 1

### PerplexityBot (Perplexity — AI search indexer)

- `/product/example` — 1
- Status codes: 403: 1

## Caveats

- **Google AI activity is not comprehensively identifiable from these logs.** `Google-Extended` is a robots.txt control token, not a distinct request user agent; other Google fetchers may be distinguishable. Do not infer citations from crawl requests.
- **Anthropic bots (ClaudeBot, Claude-User, Claude-SearchBot) cannot be IP-verified** — Anthropic does not publish crawler IP ranges (they crawl from cloud-provider IPs). Counts for these are user-agent-only and could include impostors.
- Some vendor IP-range lists could not be fetched this run; affected bots were counted user-agent-only as unverified.
- If the site sits behind Cloudflare or another CDN, origin logs miss requests served or blocked at the edge — pull edge logs (or Cloudflare AI Crawl Control numbers) for the full picture.
