import type { Metadata } from 'next'
import { AuthProvider } from "@propelauth/nextjs/client";
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Create Next App',
  description: 'Generated by create next app',
}

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en">
      <AuthProvider authUrl={process.env.NEXT_PUBLIC_AUTH_URL!}>
      <body className={inter.className}>{children}</body>
      </AuthProvider>
    </html>
  )
}
