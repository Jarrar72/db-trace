import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DB-TRACE | AI Cloud Database Security",
  description: "Contextual Risk Detection and Verified Remediation for Cloud Database Security",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
