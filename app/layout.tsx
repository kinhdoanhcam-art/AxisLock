import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AxisLock — Role Boundary System",
  description: "Define role boundaries and prevent conflicting authority assignments on GenLayer.",
  other: { "codex-preview": "development" },
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}

