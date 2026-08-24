// x402 v2 paywall backed by the Coinbase CDP facilitator.
// Port of the proven gateway implementation (x402-facilitator/src/paywall.mjs):
// x402HTTPResourceServer emits x402Version:2 challenges (Payment-Required
// header) and verifies/settles via CDP. Replaces the legacy x402-express
// paymentMiddleware whose default facilitator cannot settle Base mainnet.
import { x402ResourceServer, x402HTTPResourceServer } from "@x402/core/server";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { createCdpAuthHeaders } from "@coinbase/x402";

const CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402";

/**
 * cfg = {
 *   enabled:       boolean              (PAID_VERIFY)
 *   payTo:         '0x...'              (X402_PAY_TO)
 *   price:         '$0.001'             (X402_PRICE_USD)
 *   publicUrl:     'https://host'       (PUBLIC_URL, https-normalized)
 *   cdpKeyId:      string               (X402_CDP_KEY_ID)
 *   cdpKeySecret:  string               (X402_CDP_KEY_SECRET)
 * }
 * Returns true when the paywall is armed.
 */
export function applyPaywall(app, cfg) {
  if (!cfg.enabled) return false;
  // Soft-fail: missing wallet/facilitator creds must never crash-loop the
  // container — fall back to gate-only mode so first-deploy boots cleanly.
  const missing = [
    ...(cfg.payTo ? [] : ['X402_PAY_TO']),
    ...(!cfg.cdpKeyId || !cfg.cdpKeySecret ? ['X402_CDP_KEY_ID/X402_CDP_KEY_SECRET'] : []),
  ];
  if (missing.length) {
    console.warn(
      `[wallet-auth] PAID_VERIFY=on but missing ${missing.join(', ')} — ` +
      `running gate-only (paid oracle disabled, /v1/verify serves free). ` +
      `Set these vars or PAID_VERIFY=off to silence this warning.`,
    );
    return false;
  }

  const publicUrl = String(cfg.publicUrl || "").replace(/\/+$/, "");
  const resourceUrl = `${publicUrl}/v1/verify`;
  const routes = {
    "/v1/verify": {
      accepts: {
        scheme: "exact",
        payTo: cfg.payTo,
        price: cfg.price || "$0.001",
        network: "eip155:8453",
        maxTimeoutSeconds: 60,
        resource: resourceUrl,
      },
      resource: resourceUrl,
      description: "Wallet signature verification (SIWE / Nostr / Solana)",
      mimeType: "application/json",
      serviceName: "wallet-auth",
      tags: ["auth", "wallet", "siwe", "nostr", "solana"],
    },
  };

  const facilitator = new HTTPFacilitatorClient({
    url: CDP_FACILITATOR_URL,
    createAuthHeaders: createCdpAuthHeaders(cfg.cdpKeyId, cfg.cdpKeySecret),
  });
  const resourceServer = new x402ResourceServer([facilitator]);
  resourceServer.register("eip155:8453", new ExactEvmScheme());
  const httpServer = new x402HTTPResourceServer(resourceServer, routes);

  // initialize() fetches supported kinds from the facilitator. If CDP creds
  // are wrong this fails; inject the known CDP kind so challenges still build.
  const ready = (async () => {
    try {
      await resourceServer.initialize();
    } catch (err) {
      console.warn("[x402] initialize failed — injecting known CDP supported kind:", err.message);
      const mapV2 = resourceServer.supportedResponsesMap.get(2) || new Map();
      const mapNet = mapV2.get("eip155:8453") || new Map();
      mapNet.set("exact", {
        kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453", extra: {} }],
        extensions: [],
        signers: {},
      });
      mapV2.set("eip155:8453", mapNet);
      resourceServer.supportedResponsesMap.set(2, mapV2);
    }
  })();

  app.use((req, res, next) => {
    if (!(req.method === "POST" && req.path === "/v1/verify")) return next();
    ready
      .then(() => handle(req, res, next, httpServer))
      .catch(next);
  });
  return true;
}

function handle(req, res, next, httpServer) {
  const adapter = makeHTTPAdapter(req);
  httpServer
    .processHTTPRequest({ adapter, path: req.path, method: req.method })
    .then((result) => {
      if (result.type === "no-payment-required") {
        return next();
      }
      if (result.type === "payment-error") {
        res.setHeader("Content-Type", result.response.isHtml ? "text/html" : "application/json");
        for (const [k, v] of Object.entries(result.response.headers)) {
          res.setHeader(k, v);
        }
        // v2 spec: WWW-Authenticate: x402 and Allow: POST for payment required.
        if (!res.getHeader("www-authenticate")) res.setHeader("WWW-Authenticate", "x402");
        if (!res.getHeader("allow")) res.setHeader("Allow", "POST");
        // v2 puts PaymentRequired in the PAYMENT-REQUIRED header (base64).
        const prHeader =
          result.response.headers["payment-required"] ||
          result.response.headers["Payment-Required"] ||
          result.response.headers["PAYMENT-REQUIRED"];
        if (prHeader) {
          try {
            const decoded = Buffer.from(prHeader, "base64").toString("utf-8");
            return res.status(result.response.status).json(JSON.parse(decoded));
          } catch {
            /* fall through to library body */
          }
        }
        return res.status(result.response.status).json(result.response.body);
      }
      // payment-verified: handler runs, then settle on response finish.
      res.locals.x402CancellationDispatcher = result.cancellationDispatcher;
      res.locals.x402BeforeHandlerSettlement = result.beforeHandlerSettlement;
      res.locals.x402PaymentPayload = result.paymentPayload;
      res.locals.x402PaymentRequirements = result.paymentRequirements;
      res.locals.x402DeclaredExtensions = result.declaredExtensions;
      settleAfterHandler(req, res, httpServer);
      next();
    })
    .catch((err) => {
      console.error("[x402] processHTTPRequest error:", err);
      res.status(402).json({ error: "Failed to verify payment" });
    });
}

function settleAfterHandler(req, res, httpServer) {
  res.on("finish", () => {
    const payload = res.locals.x402PaymentPayload;
    const requirements = res.locals.x402PaymentRequirements;
    const declaredExtensions = res.locals.x402DeclaredExtensions;
    const beforeSettle = res.locals.x402BeforeHandlerSettlement;
    if (!payload || !requirements) return;

    let transportContext;
    try {
      transportContext = {
        request: { adapter: makeHTTPAdapter(req), path: req.path, method: req.method },
      };
    } catch {
      return;
    }

    httpServer
      .processSettlement(payload, requirements, declaredExtensions, transportContext, undefined, beforeSettle)
      .then((settleResult) => {
        if (res.writableEnded) return;
        if (settleResult.success && settleResult.headers) {
          for (const [k, v] of Object.entries(settleResult.headers)) {
            if (!res.getHeader(k)) res.setHeader(k, v);
          }
        }
      })
      .catch((err) => console.error("[x402] processSettlement error:", err));
  });
}

function makeHTTPAdapter(req) {
  return {
    getHeader(name) {
      return req.get(name);
    },
    getMethod() {
      return req.method;
    },
    getPath() {
      return req.path;
    },
    getUrl() {
      // Advertise https in the challenge — Railway edge terminates TLS.
      const publicUrl = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");
      if (publicUrl) return `${publicUrl}${req.originalUrl || req.url}`;
      return `${req.protocol}://${req.headers.host}${req.originalUrl || req.url}`;
    },
    getAcceptHeader() {
      return req.get("Accept") || "";
    },
    getUserAgent() {
      return req.get("User-Agent") || "";
    },
    getQueryParams() {
      return req.query;
    },
    getBody() {
      return req.body;
    },
  };
}
