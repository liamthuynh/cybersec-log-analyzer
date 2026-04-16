import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'CyberScope — Log Analyzer',
  description: 'AI-powered cybersecurity log analysis for SOC analysts',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-cyber-bg text-cyber-text antialiased">
        {children}
      </body>
    </html>
  );
}
