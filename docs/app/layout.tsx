import "./global.css"
import { Analytics } from "./analytics"
import { RootProvider } from "fumadocs-ui/provider/next"
import type { ReactNode } from "react"

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
  // No font loader. Zen ships inside @hanzo/design and global.css declares the
  // faces, so there is no generated family name to bind here.
  return (
    <html lang="en" suppressHydrationWarning>
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
