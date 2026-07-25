# Spook Shack source connector research

Date: 2026-07-25

This note summarizes first-party API/documentation for the connectors in `spook_shack/intel.py` and records the changes applied in this repo.

## Sources consulted

- Ransomware.live API comparison page: https://www.ransomware.live/api
- Ransomware.live Pro API docs: https://api-pro.ransomware.live/docs
- Ransomware.live Pro Swagger spec: https://api-pro.ransomware.live/swagger.json
- Ransomware.live public v2 docs: https://www.ransomware.live/apidocs
- Have I Been Pwned API docs: https://haveibeenpwned.com/api/v3
- PhishHunt API docs: https://phishunt.io/api/
- Telethon TelegramClient docs: https://docs.telethon.dev/en/stable/modules/client.html
- Telethon signing-in docs: https://docs.telethon.dev/en/stable/basic/signing-in.html
- TweetFeed feeds page: https://tweetfeed.live/feeds/

## Current code locations

- Ransomware.live connector: `spook_shack/intel.py:303-323`
- PhishHunt connector: `spook_shack/intel.py:326-336`
- TweetFeed connector: `spook_shack/intel.py:339-356`
- Have I Been Pwned connector: `spook_shack/intel.py:359-383`
- Telegram connector: `spook_shack/intel.py:386-424`

## Findings by connector

### 1) ransomware.live — switched to the Pro API

**What the first-party docs say**

- The Pro API is documented separately from the public/free v2 API and is served from `https://api-pro.ransomware.live/` with docs at `https://api-pro.ransomware.live/docs`. The API comparison page says the Pro API requires an API key and offers the higher-tier feature set, while the free v2 API is separate and limited. Sources: https://www.ransomware.live/api, https://api-pro.ransomware.live/docs
- The Pro Swagger spec defines a global API key security scheme named `apikey` with an `X-API-KEY` header. Source: https://api-pro.ransomware.live/swagger.json
- The Pro docs list the victims endpoint as `GET /victims/recent` and describe it as returning the 100 most recent active victims, with an `order` query parameter (`discovered` or `attacked`). Source: https://api-pro.ransomware.live/swagger.json
- The public/free docs on `https://www.ransomware.live/apidocs` are for `https://api.ransomware.live/v2` and list a different legacy endpoint (`/recentvictims`), which is not the Pro API the user asked us to follow. Source: https://www.ransomware.live/apidocs

**Implications for Spook Shack**

- The previous connector called `https://api.ransomware.live/v2/recentvictims` without an auth header (`spook_shack/intel.py:303-305`), which matched the free/public v2 docs, not the Pro API.
- The connector now calls the Pro host and Pro endpoint and sends `X-API-KEY`.
- The Pro response schema includes `victim`, `group`, `attackdate`, `discovered`, `country`, `activity`, `website`, `screenshot`, `infostealer`, `press`, `id`, and `permalink`. Source: https://api-pro.ransomware.live/swagger.json
- The ransomware.live connector now maps `permalink` into `link` so `_records_from_feed_item()` preserves the victim source URL. Current mapping logic: `spook_shack/intel.py:285-290`.

**Recommended connector changes**

1. Change the base URL to `https://api-pro.ransomware.live`.
2. Call `GET /victims/recent` instead of `/v2/recentvictims`.
3. Add the `X-API-KEY` request header from connector credentials/config.
4. Pass `order=discovered` unless there is a deliberate reason to use `attacked`.
5. Map `permalink` to `link`/`url` so downstream record creation preserves a usable `source_url`.
6. Re-check field extraction against the Pro payload, especially if you want to surface `website`, `activity`, or `screenshot` as observables or metadata.

### 2) Have I Been Pwned — current endpoint is fine, but the key is not needed for `/breaches`

**What the first-party docs say**

- The API base URL is `https://haveibeenpwned.com/api/v3`. Source: https://haveibeenpwned.com/api/v3
- Authorization is required for email-address, domain, pastes, and stealer-log endpoints; the docs explicitly do **not** require authorization for the public `breaches` endpoint or the free Pwned Passwords API. Source: https://haveibeenpwned.com/api/v3
- Requests must include a `user-agent` header, and a missing user agent returns HTTP 403. Source: https://haveibeenpwned.com/api/v3
- The `GET /breaches` endpoint returns all breached sites in the system. Source: https://haveibeenpwned.com/api/v3
- Requests to the breaches/pastes/stealer-log APIs are rate-limited, with HTTP 429 and `retry-after` guidance for paid tiers. Source: https://haveibeenpwned.com/api/v3

**Implications for Spook Shack**

- The current connector already targets `https://haveibeenpwned.com/api/v3/breaches` and sends a user agent (`spook_shack/intel.py:359-366`), which aligns with the docs.
- The connector currently adds `hibp-api-key` if present, but that header is not required for `/breaches`; it is only required for auth-protected endpoints. Source: https://haveibeenpwned.com/api/v3
- The current field mapping (`Title`, `Name`, `Domain`, `BreachDate`, `AddedDate`, `DataClasses`) matches the breach model shown in the docs. Source: https://haveibeenpwned.com/api/v3

**Recommended connector changes**

- No mandatory API-path change is needed for the current `/breaches` use case.
- Optional cleanup: make it explicit in code/config that the API key is not needed for this connector unless the implementation later expands to auth-protected HIBP endpoints.

### 3) PhishHunt — current endpoint is correct, but pagination is incomplete

**What the first-party docs say**

- The API endpoint is `GET https://phishunt.io/api/v1/domains`. Source: https://phishunt.io/api/
- The API is open/free and requires no auth. Source: https://phishunt.io/api/
- Supported query parameters include `limit`, `offset`, `format`, `company`, and `since`. Source: https://phishunt.io/api/
- `limit` maxes out at 1000 when set, and omitting `limit` returns all current results. Source: https://phishunt.io/api/
- The feed is refreshed hourly, and the docs state a rate limit of 10 requests/sec per IP. Source: https://phishunt.io/api/

**Implications for Spook Shack**

- The current connector calls `https://phishunt.io/api/v1/domains?limit=200&format=json` (`spook_shack/intel.py:326-336`). That is a valid request, but it only fetches the first page and can miss later results.
- Because the docs expose `offset`/`limit` pagination and allow up to 1000 results per page, the connector should either:
  - request `limit=1000` and accept a single large page, or
  - iterate `offset` until `count` is exhausted.
- The current response parsing expects `results` or a raw list, which is compatible with the documented JSON shape.

**Recommended connector changes**

1. Add pagination (`offset`) so the connector drains the full feed, not just the first 200 rows.
2. Consider increasing `limit` to 1000 if a one-request-per-run pattern is preferred.
3. Keep `format=json`; that is supported and appropriate for the current parser.

### 4) Telegram / Telethon — current usage matches the official client pattern

**What the first-party docs say**

- A client is created with `TelegramClient(name, api_id, api_hash)`. Source: https://docs.telethon.dev/en/stable/modules/client.html
- Starting as a bot uses `await client.start(bot_token=bot_token)`. Starting as a user uses `await client.start(phone)`. Source: https://docs.telethon.dev/en/stable/basic/signing-in.html, https://docs.telethon.dev/en/stable/modules/client.html
- `iter_messages(...)` returns messages for a chat/entity and defaults to newest-to-oldest order. Source: https://docs.telethon.dev/en/stable/modules/client.html
- The docs note flood-wait behavior for `GetHistoryRequest` and that `wait_time` defaults to 1 second for this limit. Source: https://docs.telethon.dev/en/stable/modules/client.html

**Implications for Spook Shack**

- The current async connector creates `TelegramClient(session_name, int(api_id), str(api_hash))`, then starts with either `bot_token` or `phone`, and iterates messages with `client.iter_messages(channel, limit=limit)` (`spook_shack/intel.py:386-424`). That matches the documented Telethon usage.
- The connector’s requirement that either `bot_token` or `phone` be present is an application policy, not a Telethon API requirement.

**Recommended connector changes**

- No API-call change is required based on the official Telethon docs.
- Optional operational enhancement: consider making `wait_time` explicit if you want a different crawl cadence than Telethon’s default.

### 5) TweetFeed RSS — current connector matches the public feed

**What the first-party docs say**

- TweetFeed publishes a public RSS feed at `https://tweetfeed.live/rss.xml`. Source: https://tweetfeed.live/feeds/
- The feed page says the IOC feeds are free/public and refreshed every 15 minutes, with no registration or API key required. Source: https://tweetfeed.live/feeds/
- The site also exposes per-tag, per-type, and per-user RSS feeds, but the root RSS feed is the general public feed. Source: https://tweetfeed.live/feeds/

**Implications for Spook Shack**

- The current connector fetches `https://tweetfeed.live/rss.xml` and parses it as RSS (`spook_shack/intel.py:339-356`), which is aligned with the docs.
- The generic RSS mapping already has `link`, `id/guid`, `title`, and `published` handling, so it should work well with the feed format.

**Recommended connector changes**

- No connector change is required for the RSS fetch itself.
- Optional metadata cleanup: the seed data currently labels TweetFeed’s `url` as `https://x.com` even though the connector and feed are on `tweetfeed.live` (`app/main.py:90`). That is not a connector bug, but it may be worth correcting if the source metadata is used in the UI.

## Short change list

1. **ransomware.live**: move from the free v2 endpoint to the Pro API, add `X-API-KEY`, use `/victims/recent`, and preserve `permalink` as `source_url`.
2. **PhishHunt**: add pagination or raise `limit` to 1000 so the connector pulls the full dataset.
3. **Have I Been Pwned**: no endpoint change needed for `/breaches`; keep the user-agent and treat the API key as optional for this connector.
4. **Telethon**: no connector change needed; current usage matches the docs.
5. **TweetFeed**: no connector change needed; the RSS URL is correct. Optional metadata cleanup only.

## Notes

- The ransomware.live public/free API docs and Pro API docs are different products. The user specifically asked to follow the Pro docs, so the free endpoint used in the current code should not be treated as authoritative here.
- I did not modify any source files.
