"use client"

import { AnalyticsProvider, usePageview } from "@hanzo/event/react"
import { usePathname } from "next/navigation"

/** The ONE Hanzo Cloud telemetry front door — POST api.hanzo.ai/v1/event. Cloud
 *  fans the one batched stream out to the web (analytics), product (insights) and
 *  error (sentry) lenses; the client never sends the org — Cloud resolves the
 *  tenant server-side from the publishable ingest key. */
const HOST = "https://api.hanzo.ai"

/** Publishable ingest key (pk_…), minted per org via POST /v1/ingest/keys. Docs
 *  readers are logged out, so no bearer can ride the request — this write-only,
 *  bundle-safe key IS how anonymous pageviews and errors resolve to an org.
 *  Unset → events are best-effort and dropped at the edge. */
const INGEST_KEY = process.env.NEXT_PUBLIC_PUBLISHABLE_KEY?.trim() || undefined

/** Honor an explicit browser opt-out (Global Privacy Control, then legacy DNT).
 *  SSR (no navigator) defaults to consented; the browser reads the real signal on
 *  hydration. Opting out suppresses pageviews AND errors. */
function consented(): boolean {
  if (typeof navigator === "undefined") return true
  const nav = navigator as Navigator & {
    globalPrivacyControl?: boolean
    doNotTrack?: string | null
  }
  if (nav.globalPrivacyControl === true) return false
  const dnt = nav.doNotTrack
  return dnt !== "1" && dnt !== "yes"
}

function Pageview() {
  usePageview(usePathname())
  return null
}

/**
 * Telemetry root. The provider owns the ONE @hanzo/event client: it fires the
 * first pageview, registers auto error capture (window.onerror +
 * unhandledrejection) and flushes on unload; <Pageview> adds one per client-side
 * route change. Errors are just events on that one stream — no separate DSN.
 */
export function Analytics() {
  return (
    <AnalyticsProvider
      config={{
        product: "mpc-docs",
        host: HOST,
        ingestKey: INGEST_KEY,
        enabled: consented(),
      }}
    >
      <Pageview />
    </AnalyticsProvider>
  )
}
