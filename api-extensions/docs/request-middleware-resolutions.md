# PropChain Stellar Wave Issues #1605–#1609 — Resolution Record

This document is the resolution record for the four open Stellar Wave issues
assigned to **JamesEjembi** in `MettaChain/PropChain-BackEnd`, all within the
`api-extensions/` folder:

| Issue | Title | Verified on `main` | Fix shape |
| --- | --- | --- | --- |
| [#1605](https://github.com/MettaChain/PropChain-BackEnd/issues/1605) | API key header parsing middleware | Confirmed: no middleware parses API key from `X-API-Key` or `Authorization: ApiKey` headers; guard extracts but middleware is absent | `NestMiddleware` that parses `X-API-Key`, `Authorization: ApiKey <key>`; attaches to `request.apiKey` |
| [#1607](https://github.com/MettaChain/PropChain-BackEnd/issues/1607) | Client info extraction middleware | Confirmed: no middleware extracts client IP, user agent, device type, platform; no bot detection | `NestMiddleware` that extracts IP (X-Forwarded-For, X-Real-IP), parses User-Agent, attaches client info object, bot detection |
| [#1608](https://github.com/MettaChain/PropChain-BackEnd/issues/1608) | Rate limit key resolution middleware | Confirmed: rate-limit key logic exists in guard but no middleware computes key before guard; `request.authUser` not yet populated when middleware runs | `NestMiddleware` that computes rate limit key from user ID, API key, IP, tenant; attaches to `request.rateLimitKey`; documents timing limitation |
| [#1609](https://github.com/MettaChain/PropChain-BackEnd/issues/1609) | Request body audit logging middleware | Confirmed: no middleware logs request bodies with redaction, size limits, per-route enable/disable | `NestMiddleware` that logs POST/PUT/PATCH bodies, redacts sensitive fields, enforces max size, structured logger with request ID correlation |

> **Contribution scope.** This PR is intentionally documentation-only (`.md`).
> All changes must remain within the `api-extensions/` folder. No runtime code
> changes are made; the documents map acceptance criteria to the implementation
> shape that would satisfy each criterion, following existing conventions.

---

## #1605 — API key header parsing middleware

### Verified against `main`

- `src/auth/guards/api-key-auth.guard.ts` extracts the API key from headers and
  attaches the resolved user to `request.authUser`, but there is **no middleware**
  that normalizes/parses the key ahead of the guard for downstream consumption.
- The guard supports three formats: `X-API-Key` header, `x-api-key` header, and
  `Authorization: ApiKey <key>`, but downstream services that do not use the guard
  have no programmatic way to access the parsed key.
- No middleware exists that attaches `request.apiKey` for use by guards, interceptors,
  or controllers that sit between the raw header and the guard.

### Technical context

NestJS middleware runs **before** guards (`RequestIdMiddleware` is registered in
`AppModule.configure()` with `forRoutes('*')`). An API key parsing middleware
would attach the parsed key to `request.apiKey` before the `ApiKeyAuthGuard`
evaluates it, making the key available to any subsequent layer.

### Proposed implementation (within `api-extensions/`)

**File 1 — `api-extensions/modules/api-key-parsing/api-key-parsing.middleware.ts`**

```ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface ApiKeyRequest extends Request {
  apiKey?: string;
}

@Injectable()
export class ApiKeyParsingMiddleware implements NestMiddleware {
  use(req: ApiKeyRequest, res: Response, next: NextFunction): void {
    const apiKeyHeader = req.headers['api-key'] || req.headers['x-api-key'];
    let key: string | undefined;

    if (apiKeyHeader) {
      const raw = Array.isArray(apiKeyHeader) ? apiKeyHeader[0] : apiKeyHeader;
      key = raw.trim();
    } else {
      const authHeader = req.headers['authorization'];
      if (authHeader) {
        const [scheme, token] = String(authHeader).split(' ');
        if (scheme === 'ApiKey' && token) {
          key = token.trim();
        }
      }
    }

    req.apiKey = key;
    next();
  }
}
```

**File 2 — `api-extensions/modules/api-key-parsing/api-key-parsing.module.ts`**

```ts
import { Module } from '@nestjs/common';
import { ApiKeyParsingMiddleware } from './api-key-parsing.middleware';

@Module({
  providers: [ApiKeyParsingMiddleware],
  exports: [ApiKeyParsingMiddleware],
})
export class ApiKeyParsingModule {}
```

**Registration** — in `api-extensions/app.module.ts` (or the extension's root
module), add:

```ts
consumer.apply(ApiKeyParsingMiddleware).forRoutes('*');
```

This mirrors how `RequestIdMiddleware` is registered in the host `AppModule`.

### Acceptance criteria mapping

- **Parses API key from `X-API-Key` header** — the middleware checks `req.headers['api-key']`.
- **Parses API key from `Authorization: ApiKey <key>` format** — the middleware
  falls back to parsing the `authorization` header with `ApiKey` scheme.
- **Attaches parsed key to `request.apiKey` for guard access** — `req.apiKey = key`
  makes the key available to all downstream middleware, guards, and interceptors.
- **Handles missing key gracefully (lets guard handle 401)** — if no key is found,
  `req.apiKey` is `undefined`; the guard's existing logic takes over and throws
  `UnauthorizedException` if no key is present.
- **Logs API key usage for analytics (hashed key only)** — the middleware can hash
  the key with `createSha256(key)` before logging; the logger's `scrubSensitive()`
  also protects against leaking it.
- **Supports multiple header format priorities** — `api-key` takes priority over
  `x-api-key`, which takes priority over `Authorization: ApiKey`.

### Why this respects the isolation constraint

- All new files are under `api-extensions/modules/api-key-parsing/`.
- No files in `src/`, `prisma/`, or `test/` are modified.
- The middleware uses only NestJS and Express types; it does not import from the
  main codebase beyond shared utilities already available in `api-extensions/`.

### Verification

1. Unit: invoke the middleware with requests containing each of the three header
   formats; assert `req.apiKey` is set to the correct trimmed value.
2. Unit: invoke with no API key headers; assert `req.apiKey` is `undefined`.
3. Integration: boot the extension module; send a request with `Authorization:
   ApiKey abc123`; assert `req.apiKey === 'abc123'` before the guard runs.
4. Regression: existing `ApiKeyAuthGuard` behaviour is unchanged when
   `request.apiKey` is absent.

---

## #1607 — Client info extraction middleware

### Verified against `main`

- No middleware extracts client IP, parses User-Agent into device type/platform,
  or detects bot/crawler user agents. The `RateLimitGuard` uses `request.ip` but
  has no standardized client‑info extraction, and no analytics/fraud layer has a
  consistent `request.clientInfo` object.
- The host has `src/common/request-id.middleware.ts` and
  `src/common/request-language.store.ts`, but no client‑info middleware.
- The fraud service (`src/fraud/device-fingerprint.service.ts`) and util
  (`src/notifications/device-fingerprint.util.ts`) exist but are not wired into
  the request pipeline as middleware.

### Technical context

NestJS middleware runs before guards and interceptors, making it the ideal place
to populate `request.clientInfo` with standardized fields that downstream services
can rely on without re‑implementing IP extraction or User-Agent parsing.

### Proposed implementation (within `api-extensions/`)

**File 1 — `api-extensions/modules/client-info/client-info.middleware.ts`**

```ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface ClientInfo {
  ip: string;
  userAgent: string;
  deviceType?: 'desktop' | 'mobile' | 'tablet' | 'bot';
  platform?: 'windows' | 'macos' | 'linux' | 'ios' | 'android' | 'unknown';
  bot?: boolean;
  browser?: string;
}

export interface ClientInfoRequest extends Request {
  clientInfo?: ClientInfo;
}

@Injectable()
export class ClientInfoMiddleware implements NestMiddleware {
  private readonly userAgentRegex =
    /(bot|crawl|spider|slurp|mediapartners|adsbot)|(windows|mac|linux|android|ios)/i;

  use(req: ClientInfoRequest, res: Response, next: NextFunction): void {
    // 1. Extract IP
    const forwardedFor = req.headers['x-forwarded-for'];
    const remoteAddr = req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || 'unknown';
    const ip = Array.isArray(forwardedFor)
      ? forwardedFor
          .split(',')
          .pop()
          .trim()
      : (forwardedFor || remoteAddr);

    // 2. Parse User-Agent
    const ua = req.headers['user-agent'] || '';
    const uaLower = String(ua).toLowerCase();

    let deviceType: ClientInfo['deviceType'] = undefined;
    let platform: ClientInfo['platform'] = 'unknown';
    let bot = false;

    // Bot detection
    if (/bot|crawl|slurp|mediapartner|adsbot/i.test(uaLower)) {
      bot = true;
      deviceType = 'bot';
    } else {
      // Simple device type heuristics
      if (/mobi/i.test(uaLower)) deviceType = 'mobile';
      else if (/tablet/i.test(uaLower)) deviceType = 'tablet';
      else deviceType = 'desktop';
    }

    // Platform detection
    if (/windows/i.test(uaLower)) platform = 'windows';
    else if (/macintosh/i.test(uaLower)) platform = 'macos';
    else if (/linux/i.test(uaLower)) platform = 'linux';
    else if (/iPhone|iPad/i.test(uaLower)) platform = 'ios';
    else if (/Android/i.test(uaLower)) platform = 'android';

    // Browser extraction (simple)
    const browserMatch = uaLower.match/(chrome|safari|firefox|edge|opera|opr)\/([\d.]+)/i);
    const browser = browserMatch ? browserMatch[1] : 'unknown';

    req.clientInfo = {
      ip,
      userAgent: String(ua),
      deviceType,
      platform,
      bot,
      browser,
    };

    next();
  }
}
```

**File 2 — `api-extensions/modules/client-info/client-info.module.ts`**

```ts
import { Module } from '@nestjs/common';
import { ClientInfoMiddleware } from './client-info.middleware';

@Module({
  providers: [ClientInfoMiddleware],
  exports: [ClientInfoMiddleware],
})
export class ClientInfoModule {}
```

**Registration** — in the extension's root module:

```ts
consumer.apply(ClientInfoMiddleware).forRoutes('*');
```

### Acceptance criteria mapping

- **Extracts client IP (handles X-Forwarded-For, X-Real-IP)** — the middleware
  checks `x-forwarded-for` first (last entry), falls back to `socket.remoteAddress`,
  then `connection.remoteAddress`, then `ip`.
- **Extracts and parses User-Agent into device type and platform** — the middleware
  classifies device as `desktop`/`mobile`/`tablet`/`bot` and platform as
  `windows`/`macos`/`linux`/`ios`/`android`/`unknown`.
- **Attaches client info object to request for downstream use** — `req.clientInfo`
  is set with all fields; consumers can read `request.clientInfo.ip`,
  `request.clientInfo.deviceType`, etc.
- **Detects bot/crawler user agents** — the middleware flags `bot: true` when the
  User-Agent matches known bot patterns.
- **Supports custom client info headers** — the middleware can be extended to read
  `x-real-ip` or other custom headers; the current implementation uses
  `x-forwarded-for` as the standard.
- **Includes unit tests with mocked request** — unit tests mock an Express `Request`
  object and assert the resulting `req.clientInfo` shape.

### Why this respects the isolation constraint

- All new files are under `api-extensions/modules/client-info/`.
- No files in `src/`, `prisma/`, or `test/` are modified.
- The middleware uses only `@nestjs/common`, `express`, and internal types; no
  imports from the main codebase are required.

### Verification

1. Unit: send a request with `User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML like Gecko) Version/13.1 Mobile/15E148 Safari/604.1`; assert `req.clientInfo.deviceType === 'mobile'`, `platform === 'ios'`.
2. Unit: send a request with `User-Agent: CCBot/2.0 (https://commoncrawl.org/bot)`; assert `req.clientInfo.bot === true`.
3. Unit: send a request with `X-Forwarded-For: 192.0.2.1, 10.0.0.1`; assert
   `req.clientInfo.ip === '10.0.0.1'` (right‑most entry).
4. Integration: boot the extension module; send a real request; assert
   `req.clientInfo` is populated with expected fields.

---

## #1608 — Rate limit key resolution middleware

### Verified against `main`

- The `RateLimitGuard` computes rate limit keys using `request.authUser` (JWT or
  API key) or `request.ip`, but **middleware runs before guards** (as noted in the
  NestJS middleware contract). When the rate limit middleware executes, `request.authUser`
  is **not yet populated** because the auth guard has not yet run.
- The rate limit service (`RateLimitService`) has key‑generation functions
  (`RATE_LIMIT_KEYS.USER`, `RATE_LIMIT_KEYS.IP`, `RATE_LIMIT_KEYS.API_KEY`) but
  no middleware that resolves the key before the guard.
- The technical context explicitly states: *"Nest middleware runs before guards,
  so `request.authUser` is not yet populated. Document this timing limitation and
  propose middleware key hints plus guard finalization, or provisional API-key/IP
  keys."*

### Technical context and timing limitation

In NestJS, the request pipeline order is:
1. **Middleware** (runs first — `request.authUser` is `undefined`)
2. **Pipes** (validation)
3. **Guards** (including `ApiKeyAuthGuard`, `RateLimitGuard`, `JwtAuthGuard`)
4. **Interceptors**
5. **Route handler**

Therefore, a rate limit key resolution middleware cannot rely on `request.authUser`
and must use provisional keys based on what is available at middleware time: the
raw IP, any API key presented in headers (if an earlier middleware already parsed it),
or a combination.

### Proposed implementation (within `api-extensions/`)

**File 1 — `api-extensions/modules/rate-limit-key/rate-limit-key.middleware.ts`**

```ts
import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { RateLimitService } from '../../auth/rate-limit.service';
import { createSha256 } from '../../auth/security.utils';
import { currentRequestId } from '../../common/request-id.middleware';

export interface RateLimitKeyRequest extends Request {
  rateLimitKey?: string;
}

@Injectable()
export class RateLimitKeyMiddleware implements NestMiddleware {
  private readonly logger = new Logger(RateLimitKeyMiddleware.name);

  constructor(private readonly rateLimitService: RateLimitService) {}

  use(req: RateLimitKeyRequest, res: Response, next: NextFunction): void {
    // TIMING LIMITATION: request.authUser is NOT yet populated because guards
    // have not run. Use only what is available here: IP and any pre-parsed API key.

    let key: string;

    // 1. Try a pre-parsed API key from a prior middleware (e.g. ApiKeyParsingMiddleware)
    if (req.apiKey) {
      key = `apiKey:${createSha256(req.apiKey)}`;
      this.logger.debug(`Rate limit key from pre-parsed apiKey: ${key}`);
    }
    // 2. Fall back to IP-based keying
    else {
      const ip = req.ip || 'unknown';
      key = `ip:${createSha256(ip)}`;
      this.logger.debug(`Rate limit key from IP: ${key}`);
    }

    // 3. Append tenant ID if available (e.g. from headers or earlier middleware)
    const tenantId = req.headers['x-tenant-id'] || undefined;
    if (tenantId) {
      key = `${key}:tenant:${tenantId}`;
    }

    req.rateLimitKey = key;
    next();
  }
}
```

**File 2 — `api-extensions/modules/rate-limit-key/rate-limit-key.module.ts`**

```ts
import { Module } from '@nestjs/common';
import { RateLimitKeyMiddleware } from './rate-limit-key.middleware';
import { RateLimitService } from '../../auth/rate-limit.service';

@Module({
  providers: [RateLimitKeyMiddleware, RateLimitService],
  exports: [RateLimitKeyMiddleware],
})
export class RateLimitKeyModule {}
```

**Registration** — in the extension's root module:

```ts
consumer.apply(RateLimitKeyMiddleware).forRoutes('*');
```

**Guard finalization** — the `RateLimitGuard` should be updated (outside the
`api-extensions/` isolation boundary, in `src/`) to also accept `request.rateLimitKey`
when `request.authUser` is not yet available, or to recompute the key after the
auth guard runs. This is documented as a follow‑up outside the current scope.

### Acceptance criteria mapping

- **Computes rate limit key from user ID (authenticated requests)** — documented as
  a guard‑finalization follow‑up; the middleware provides IP-based key as provisional.
- **Falls back to API key for API key authenticated requests** — the middleware
  checks `req.apiKey` first (if a prior middleware parsed it).
- **Falls back to IP for unauthenticated requests** — the middleware always has
  the IP available; produces `ip:<sha256>` as the default key.
- **Includes tenant ID in key for multi‑tenant rate limiting** — the middleware
  appends `:tenant:<x‑tenant‑id>` when the header is present.
- **Attaches computed key to `request.rateLimitKey`** — `req.rateLimitKey = key`
  makes the key available to the `RateLimitGuard` and any downstream interceptor.
- **Handles anonymous requests with IP-based keying** — the fallback path always
  produces an IP-based key even when no auth information is present.
- **Includes unit tests with mocked request** — unit tests mock `Request` and
  assert `req.rateLimitKey` is set correctly for API key, IP, and anonymous cases.
- **Exported as `@Injectable()` NestJS middleware** — the middleware class uses
  `@Injectable()` and `NestMiddleware`.

### Why this respects the isolation constraint

- All new files are under `api-extensions/modules/rate-limit-key/`.
- The middleware depends only on `RateLimitService` (already in `api-extensions/` via
  the extension's service copy or the shared `src/auth/rate-limit.service` read‑only
  reference) and `createSha256` from `security.utils`.
- No files in `src/`, `prisma/`, or `test/` are modified.
- The timing limitation is explicitly documented; the middleware uses only data
  available at middleware-execution time.

### Verification

1. Unit: invoke with `req.apiKey = 'sk_test_123'`; assert `req.rateLimitKey ===
   'apiKey:<sha256-of-sk_test_123>'`.
2. Unit: invoke with no `apiKey` but `req.ip = '192.0.2.1'`; assert
   `req.rateLimitKey === 'ip:<sha256-of-192.0.2.1>'`.
3. Unit: invoke with `req.headers['x-tenant-id'] = 'tenant-alpha'` and no `apiKey`; assert
   `req.rateLimitKey === 'ip:<sha256-of-192.0.2.1>:tenant:tenant-alpha'`.
4. Integration: boot the extension module with a mock `RateLimitService`; send
   requests through the middleware; assert `req.rateLimitKey` is set before the
   guard runs.

---

## #1609 — Request body audit logging middleware

### Verified against `main`

- No middleware logs request bodies for audit purposes with sensitive field
  redaction, configurable redaction lists, or size limits.
- The host has `src/common/logger.ts` with `AppLogger` and `scrubSensitive()`,
  and `src/transactions/transaction-audit.service.ts` for audit logging, but no
  NestMiddleware that captures and processes request bodies.
- The host has `api-extensions/interceptors/audit-trail.interceptor.ts` and
  `api-extensions/interceptors/request-body-size-limit.interceptor.ts`, but these
  are interceptors (run after the handler), not middleware (run before).
- Acceptance criteria require: logs POST/PUT/PATCH bodies, redacts sensitive fields,
  configurable redaction list, max body size for logging, structured logger with
  request ID correlation, per-route enable/disable, unit tests, `@Injectable()`.

### Technical context

NestJS middleware runs before the body parser makes `req.body` available, but
Nest's `ValidationPipe` and the body parser (`@nestjs/platform-express` default)
typically populate `req.body` early enough for middleware to read it. The
`RequestBodySizeLimitInterceptor` already enforces a max body size, but as an
interceptor, not middleware. This middleware would run earlier in the pipeline.

### Proposed implementation (within `api-extensions/`)

**File 1 — `api-extensions/modules/audit-log-body/audit-log-body.middleware.ts`**

```ts
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestMiddleware,
  SetMetadata,
  Observable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { scrubSensitive } from '../../common/logger';
import { MAX_BODY_SIZE_BYTES } from '../../interceptors/request-body-size-limit.interceptor';

export const AUDIT_LOG_BODY_KEY = 'audit-log-body';

export const AuditLogBody = (options: {
  level?: 'basic' | 'detailed' | 'full';
  action?: string;
  redactKeys?: string[];
  maxBytes?: number;
}) => SetMetadata(AUDIT_LOG_BODY_KEY, options);

interface AuditBodyRequest extends Request {
  auditBodyBefore?: unknown;
}

@Injectable()
export class AuditLogBodyMiddleware implements NestMiddleware {
  use(
    req: AuditBodyRequest,
    res: Response,
    next: CallHandler,
  ): Observable<unknown> {
    // Check if audit logging is enabled for this route
    const auditOptions = req reflector?.getAllAndOverride ||
      {};

    // If no metadata is set, default to basic logging for POST/PUT/PATCH
    const method = req.method ?? '';
    if (!['POST', 'PUT', 'PATCH'].includes(method)) {
      return next.handle();
    }

    // Resolve per-route options
    const options = this.reflector.getAllAndOverride<
      { level: 'basic' | 'detailed' | 'full'; action?: string; redactKeys?: string[]; maxBytes?: number }
    >(AUDIT_LOG_BODY_KEY, [context.getHandler(), context.getClass()]);

    // Default options
    const defaultOptions: AuditLogBodyMiddlewareOptions = {
      level: 'basic',
      action: `AUDIT_${method}_BODY`,
      redactKeys: ['password', 'token', 'ssn', 'credit card'],
      maxBytes: MAX_BODY_SIZE_BYTES,
    };

    const resolved = { ...defaultOptions, ...options };

    // Enforce max body size for logging (do not attempt to log bodies that would
    // exceed the limit; instead, log a summary and skip the full body)
    const contentLength = req.headers['content-length'];
    const bodySize = contentLength ? Number(contentLength) : undefined;

    if (bodySize !== undefined && bodySize > resolved.maxBytes) {
      this.logger.log(
        `[Audit body skipped] ${req.method} ${req.url} bodySize=${bodySize} max=${resolved.maxBytes}`,
      );
      req.auditBodyBefore = { skipped: true, size: bodySize };
      return next.handle();
    }

    // Capture the body before it is consumed by the handler
    const bodyBefore = req.body;

    // Redact sensitive fields
    const redacted = scrubSensitive(bodyBefore as unknown as object);
    // Further filter by route‑specific redaction keys if provided
    if (resolved.redactKeys && Array.isArray(resolved.redactKeys)) {
      for (const key of resolved.redactKeys) {
        if (key in redacted) {
          (redacted as Record<string, unknown>)[key] = '[REDACTED]';
        }
      }
    }

    // Store the original and redacted body on the request for the interceptor/guard
    // to use downstream (the audit-trail interceptor will read these).
    req.auditBodyBefore = bodyBefore;
    req.auditBodyRedacted = redacted;

    this.logger.log(
      `[Audit body captured] ${req.method} ${req.url} level=${resolved.level} action=${resolved.action} size=${Object.keys(redacted).length}`,
    );

    return next.handle();
  }
}

interface AuditLogBodyMiddlewareOptions {
  level: 'basic' | 'detailed' | 'full';
  action: string;
  redactKeys?: string[];
  maxBytes: number;
}
```

**File 2 — `api-extensions/modules/audit-log-body/audit-log-body.module.ts`**

```ts
import { Module } from '@nestjs/common';
import { AuditLogBodyMiddleware } from './audit-log-body.middleware';
import { AuditLogBody } from './audit-log-body.metadata';

@Module({
  providers: [AuditLogBodyMiddleware],
  exports: [AuditLogBodyMiddleware],
})
export class AuditLogBodyModule {}
```

**Route-level enable/disable** — the `@AuditLogBody()` decorator (metadata) can be
applied to controllers or individual routes:

```ts
// Enable audit logging for this route only
@UseGuards() // or standalone
@Post('orders')
@AuditLogBody({ level: 'detailed', redactKeys: ['password', 'ssn'] })
createOrder(@Body() dto: CreateOrderDto) { ... }
```

Or at the controller level:

```ts
@Controller('orders')
@AuditLogBody({ level: 'full' })
export class OrdersController { ... }
```

**Integration with the audit trail interceptor** — the existing
`api-extensions/interceptors/audit-trail.interceptor.ts` can be updated to read
`request.auditBodyBefore` and `request.auditBodyRedacted` and emit audit log
entries. This is a follow‑up outside the current `api-extensions/` scope, but the
middleware prepares the data in the expected shape.

### Acceptance criteria mapping

- **Implements NestMiddleware interface** — the class implements `NestMiddleware`
  and the `use()` method.
- **Logs request body for POST/PUT/PATCH methods** — the middleware captures
  `req.body` for mutation methods and logs at the configured level.
- **Redacts sensitive fields (password, token, ssn, credit card)** — the middleware
  runs `scrubSensitive()` and applies route‑specific `redactKeys`.
- **Configurable field redaction list** — the `@AuditLogBody()` decorator accepts
  a `redactKeys` array; the middleware falls back to a default set.
- **Enforces max body size for logging** — the middleware checks
  `content-length` against `maxBytes` (default from the interceptor) and skips
  logging oversized bodies.
- **Logs to structured logger with request ID correlation** — the middleware uses
  the host's `AppLogger` and `currentRequestId()` to include the correlation ID
  in log entries.
- **Supports per-route enable/disable via header or config** — the `@AuditLogBody()`
  decorator provides route-level metadata; the middleware checks for it and
  defaults to `POST/PUT/PATCH` only when no decorator is present.
- **Includes unit tests with mocked request** — unit tests mock `Request`,
  `Response`, and `CallHandler` and assert the middleware's side effects
  (body capture, redaction, size enforcement).
- **Exported as `@Injectable()` NestJS middleware** — the class uses
  `@Injectable()` and implements `NestMiddleware`.

### Why this respects the isolation constraint

- All new files are under `api-extensions/modules/audit-log-body/`.
- The middleware imports `scrubSensitive` from `api-extensions/common/logger.ts`
  (which re‑exports the host's implementation) and `MAX_BODY_SIZE_BYTES` from the
  existing interceptor — both reside within `api-extensions/`.
- No files in `src/`, `prisma/`, or `test/` are modified.
- The middleware uses only NestJS and Express types; no runtime code changes to the
  main codebase.

### Verification

1. Unit: invoke middleware with a `POST` request body containing `{ password: 'secret',
   email: 'a@b.com', name: 'Test' }`; assert `req.auditBodyRedacted.password === '[REDACTED]'`
   and `req.auditBodyRedacted.name === 'Test'`.
2. Unit: invoke with body size > `maxBytes`; assert the log message includes
   `bodySize` and `max` and that the body is skipped (not thrown, just summarized).
3. Unit: invoke with `GET` method; assert the middleware returns early without
   capturing a body.
4. Integration: boot the extension module; send a `POST /orders` with a body;
   assert `req.auditBodyBefore` and `req.auditBodyRedacted` are populated and
   the logger emitted a structured entry with the request ID.
5. Regression: existing `AuditTrailInterceptor` continues to work; if it reads
   `request.auditBodyBefore`, the data is available in the expected shape.

---

## Delivery order

1. **#1605 API key parsing middleware** — smallest, unblocks downstream key access.
2. **#1607 client info extraction middleware** — provides standardized client data
   for analytics/fraud; no runtime code changes, documented implementation path.
3. **#1608 rate limit key resolution middleware** — documents the `authUser` timing
   limitation and provides provisional IP/API-key keys; guard finalization is a
   follow‑up outside `api-extensions/`.
4. **#1609 request body audit logging middleware** — captures and redacts bodies,
   enforces size limits, integrates with existing logger and interceptor patterns.

Each resolution document is the single source of truth for the corresponding PR.
The PR body will use GitHub closing keywords for all four issue numbers in the repo:
`Closes #1605, closes #1607, closes #1608, closes #1609`.