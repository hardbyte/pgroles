const withMarkdoc = require('@markdoc/next.js')
const { PHASE_DEVELOPMENT_SERVER } = require('next/constants')

const basePath = process.env.DOCS_BASE_PATH || ''

module.exports = (phase) => {
  /** @type {import('next').NextConfig} */
  const nextConfig = {
    basePath,
    assetPrefix: basePath || undefined,
    output: 'export',
    distDir:
      phase === PHASE_DEVELOPMENT_SERVER
        ? '.next'
        : process.env.NEXT_DIST_DIR || 'out',
    trailingSlash: true,
    reactStrictMode: true,
    pageExtensions: ['js', 'jsx', 'md'],
    images: {
      unoptimized: true,
    },
    experimental: {
      scrollRestoration: true,
    },
  }

  return withMarkdoc()(nextConfig)
}
