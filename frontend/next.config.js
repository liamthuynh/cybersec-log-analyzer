/** @type {import('next').NextConfig} */

// BACKEND_INTERNAL_URL is used by the Next.js server/rewrite layer.
// In Docker, it should point at the backend service name on the compose network.
// Falls back to localhost for plain `npm run dev`.
const API_URL = process.env.BACKEND_INTERNAL_URL || 'http://localhost:8000';

const nextConfig = {
  // Proxy all /api/* requests to the Flask backend — avoids CORS in the browser.
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${API_URL}/api/:path*`,
      },
    ];
  },

  // Enable standalone output so the production Docker image is minimal
  output: 'standalone',
};

module.exports = nextConfig;
