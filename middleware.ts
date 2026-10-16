import { NextResponse } from 'next/server';
import type { NextRequest, NextFetchEvent } from 'next/server';

export function middleware(request: NextRequest, event: NextFetchEvent) {
  const url = request.nextUrl.pathname;

  // Analytics are strictly opt-in. Never hard-code a collector, website ID,
  // or forward the visitor's IP from this middleware.
  const analyticsHost = process.env.UMAMI_HOST;
  const websiteId = process.env.UMAMI_WEBSITE_ID;
  if (analyticsHost && websiteId) {
    const payload = {
      hostname: request.nextUrl.hostname,
      language: request.headers.get('accept-language')?.split(',')[0] || 'en',
      referrer: request.headers.get('referer') || '',
      screen: 'unknown',
      title: 'NADIR',
      url,
      website: websiteId,
    };
    const pageView = fetch(`${analyticsHost.replace(/\/$/, '')}/api/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, type: 'event' }),
      signal: AbortSignal.timeout(1200),
    }).catch(() => {});
    event.waitUntil(pageView);
  }

  return NextResponse.next();
}

/* Assets are excluded, not just pages. MapLibre 6 loads its worker from
   /vendor/maplibre/<version>/ at runtime, and the basemap style from
   /dark-matter-style.json — neither is under _next/static, so both used to
   match here and pay two umami round trips before the map could start. That is
   the same starvation that 2f375dd fixed for the CCTV routes, moved onto the
   map's critical path. Analytics wants page views; asset fetches are not one. */
export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|vendor|favicon.ico|sitemap.xml|robots.txt|.*\\.(?:svg|png|jpg|jpeg|gif|webp|mjs|js|css|json|pbf|mvt|woff|woff2|ico|txt)$).*)',
  ],
}
