import type { CookieOptions } from 'hono/utils/cookie'

/**
 * 세션/앱 쿠키: 운영에서는 apex·www 공유를 위해 Domain=gom-hr.com.
 * localhost·LAN IP 등에서는 Domain 생략(host-only). 그렇지 않으면 브라우저가 쿠키를 버려 로그인 직후 로그아웃처럼 보임.
 *
 * HTTPS 요청에서는 Secure=true를 붙여 Safari·iOS WebView 등에서 세션이 더 잘 유지되게 한다.
 */
export function withPublicCookieDomain(reqUrl: string, opts: CookieOptions): CookieOptions {
  let isHttps = false
  let out: CookieOptions
  try {
    const url = new URL(reqUrl)
    isHttps = url.protocol === 'https:'
    const host = url.hostname
    if (host === 'gom-hr.com' || host === 'www.gom-hr.com') {
      out = { ...opts, domain: 'gom-hr.com' }
    } else {
      out = { ...opts }
      delete out.domain
    }
  } catch {
    out = { ...opts }
    delete out.domain
  }
  if (isHttps) {
    return { ...out, secure: true }
  }
  return out
}
