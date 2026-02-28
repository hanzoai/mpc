import "./global.css"
import { RootProvider } from "fumadocs-ui/provider/next"
import { Inter } from "next/font/google"
import type { ReactNode } from "react"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-geist-sans",
  display: "swap",
})

const interMono = Inter({
  subsets: ["latin"],
  variable: "--font-geist-mono",
  display: "swap",
})

export const metadata = {
  title: {
    default: "Lux MPC - Threshold Signature Documentation",
    template: "%s | Lux MPC",
  },
  description: "Multi-Party Computation for threshold signatures - ECDSA, EdDSA, and Taproot",
}

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${interMono.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-svh bg-background font-sans antialiased">
        <RootProvider
          search={{
            enabled: true,
          }}
          theme={{
            enabled: true,
            defaultTheme: "dark",
          }}
        >
          <div className="relative flex min-h-svh flex-col bg-background">
            {children}
          </div>
        </RootProvider>
        <script defer src="https://analytics.hanzo.ai/script.js" data-website-id="34538f3b-ae2f-4d86-a3a7-ba15f2fcd2c1" data-do-not-track="true" data-exclude-search="true" />
      </body>
    </html>
  )
}
