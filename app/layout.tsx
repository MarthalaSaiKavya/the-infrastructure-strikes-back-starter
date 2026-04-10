import type { ReactNode } from "react";
import { Analytics } from "@vercel/analytics/next";

export const metadata = {
  title: "The Infrastructure Strikes Back — Starter",
  description:
    "Synthetic adversarial training repo. Not production. Not a real system.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          background: "#0b0b0b",
          color: "#eaeaea",
          margin: 0,
          padding: "2rem",
          lineHeight: 1.4,
        }}
      >
        {children}
        {/* Vercel Web Analytics — tracks event traffic (pageviews, referrers).
            Opt out per deploy by removing this line or unsetting the project's
            Analytics toggle in Vercel. */}
        <Analytics />
      </body>
    </html>
  );
}
