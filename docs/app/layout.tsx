import "./global.css"
import { Analytics } from "./analytics"
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
    default: "Hanzo MPC - Threshold Signature Documentation",
    template: "%s | Hanzo MPC",
  },
  description: "Multi-Party Computation for threshold signatures - ECDSA, EdDSA, and Taproot",
  openGraph: {
    title: "Hanzo MPC",
    description: "Multi-Party Computation for threshold signatures",
    url: "https://mpc.hanzo.ai",
    siteName: "Hanzo MPC",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Hanzo MPC",
    description: "Multi-Party Computation for threshold signatures",
    creator: "@hanzoai",
  },
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
        <Analytics />
      </body>
    </html>
  )
}
