import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, deleteCookie, setCookie } from 'hono/cookie'
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from 'jose'
import { renderer } from './renderer'
import kakaoAuth from './routes/kakao'
import type { Bindings, User } from './types'

const app = new Hono<{ Bindings: Bindings }>()

const textEncoder = new TextEncoder()
const appleJwks = createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'))

const APEX_HOST = 'gom-hr.com'
const WWW_HOST = 'www.gom-hr.com'
const APEX_REDIRECT_EXCEPTIONS = new Set([
  '/auth/apple/callback',
  '/auth/kakao/callback',
])

const bytesToBase64 = (bytes: Uint8Array) => {
  let binary = ''
  const chunkSize = 0x8000
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }
  return btoa(binary)
}

const base64ToBytes = (base64: string) => {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

const formatLocalDate = (date: Date) => {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

const getTodayKst = () => {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Seoul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
  return formatter.format(new Date())
}

const derivePasswordHash = async (password: string, salt: Uint8Array, iterations: number) => {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  )
  return bytesToBase64(new Uint8Array(bits))
}

const hashPassword = async (password: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iterations = 100000
  const hash = await derivePasswordHash(password, salt, iterations)
  return `pbkdf2$${iterations}$${bytesToBase64(salt)}$${hash}`
}

const verifyPassword = async (password: string, stored: string) => {
  if (!stored.startsWith('pbkdf2$')) {
    return password === stored
  }
  const parts = stored.split('$')
  if (parts.length !== 4) {
    return false
  }
  const iterations = Number(parts[1])
  const salt = base64ToBytes(parts[2])
  const expected = parts[3]
  const actual = await derivePasswordHash(password, salt, iterations)
  return actual === expected
}

const getCoupleCode = async (db: Bindings['DB'], coupleId?: number | null) => {
  if (!coupleId) return null
  const couple = await db.prepare(
    'SELECT couple_code FROM couples WHERE id = ?'
  ).bind(coupleId).first()
  return couple ? (couple.couple_code as string) : null
}

const generateOauthState = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

const normalizeAppleKey = (value?: string) => {
  if (!value) return ''
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '')
    .replace(/\r\n/g, '\n')
    .trim()
}

const createAppleClientSecret = async (env: Bindings) => {
  const clientId = env.APPLE_CLIENT_ID
  const teamId = env.APPLE_TEAM_ID
  const keyId = env.APPLE_KEY_ID
  const privateKey = normalizeAppleKey(env.APPLE_PRIVATE_KEY)

  if (!clientId || !teamId || !keyId || !privateKey) {
    throw new Error('Apple 로그인 설정이 올바르지 않습니다.')
  }

  const key = await importPKCS8(privateKey, 'ES256')
  return await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: keyId })
    .setIssuer(teamId)
    .setSubject(clientId)
    .setAudience('https://appleid.apple.com')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(key)
}

// CORS 설정 (API 라우트용)
app.use('/api/*', cors())

// apex 도메인(gom-hr.com)은 www로 통일
// 단, OAuth 콜백(특히 Apple form_post)은 리다이렉트 시 본문 유실 가능성이 있어 예외 처리
app.use('*', async (c, next) => {
  const url = new URL(c.req.url)
  if (url.hostname === APEX_HOST && !APEX_REDIRECT_EXCEPTIONS.has(url.pathname)) {
    url.hostname = WWW_HOST
    return c.redirect(url.toString(), 301)
  }
  await next()
})

// 앱/웹 구분: Flutter 앱은 X-Gomhour-App: 1 헤더로 요청
const isFromApp = (c: any) => c.req.header('X-Gomhour-App') === '1' || getCookie(c, 'from_app') === '1'

// 소셜 로그인 라우트 등록
app.route('/auth/kakao', kakaoAuth)

// 개인정보처리방침 - /privacy는 /privacy.html로 리다이렉트, static asset 서빙
app.get('/privacy', (c) => c.redirect('/privacy.html'))

// 렌더러 미들웨어 적용
app.use(renderer)

// 앱 전용 진입점: /app 접속 시 쿠키 설정 후 로그인/대시보드로
app.get('/app', (c) => {
  setCookie(c, 'from_app', '1', { path: '/', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
  const userSessionCookie = getCookie(c, 'user_session')
  if (userSessionCookie) {
    try {
      const user = JSON.parse(userSessionCookie) as User
      if (user?.setup_done) return c.redirect('/dashboard')
      return c.redirect('/setup')
    } catch { /* invalid session */ }
  }
  return c.redirect('/app/login')
})

// 홈페이지: 웹=앱 소개만 (앱은 /app으로 진입)
app.get('/', async (c) => {
  if (isFromApp(c)) {
    const userSessionCookie = getCookie(c, 'user_session')
    if (userSessionCookie) {
      try {
        const user = JSON.parse(userSessionCookie) as User
        if (user?.setup_done) return c.redirect('/dashboard')
        return c.redirect('/setup')
      } catch { /* invalid session */ }
    }
    return c.redirect('/app/login')
  }
  return c.render(
    <div class="min-h-screen bg-gradient-to-b from-amber-50 to-white">
      <header class="bg-white/80 backdrop-blur border-b border-amber-100 sticky top-0 z-10">
        <div class="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <a href="/" class="flex items-center gap-2">
            <span class="text-2xl">🐻</span>
            <span class="font-bold text-gray-800 text-xl">곰아워</span>
          </a>
          <nav class="flex gap-6 text-sm font-medium">
            <a href="/support" class="text-gray-600 hover:text-amber-600 transition">고객지원</a>
            <a href="/privacy" class="text-gray-600 hover:text-amber-600 transition">개인정보처리방침</a>
          </nav>
        </div>
      </header>

      <section class="max-w-4xl mx-auto px-4 py-16 md:py-24 text-center">
        <h1 class="text-4xl md:text-5xl font-bold text-gray-800 mb-6">하루 한 번, 연인에게 곰아워하세요!</h1>
        <p class="text-lg md:text-xl text-gray-700 leading-relaxed whitespace-pre-line">
          {'일상이 바빠\n통화로도, 카톡으로도\n연인에게 고마운 마음을 전하지 못하고 있지는 않나요?'}
        </p>
      </section>

      <section class="max-w-4xl mx-auto px-4 pb-10">
        <div class="bg-white rounded-3xl p-8 md:p-12 shadow-lg border border-amber-100 space-y-6">
          <p class="text-gray-700 text-lg leading-relaxed">
            사랑을 표현으로 느끼는 사람들이 많아요.<br />
            마음은 있지만, 말로 꺼내기엔 하루가 너무 빠르게 지나가죠.
          </p>
          <p class="text-gray-700 text-lg leading-relaxed whitespace-pre-line">
            {'곰아워는\n하루에 한 번,\n연인에게 느낀 고마움을\n부담 없이 짧게 기록하고 전할 수 있는\n커플 관계 관리 앱이에요.'}
          </p>
          <div>
            <h2 class="text-2xl font-bold text-gray-800 mb-4">곰아워에서 할 수 있는 것들</h2>
            <ol class="space-y-3 text-gray-700 list-decimal pl-6">
              <li>하루 한 마디, 상대방에게 고마운 마음을 기록해요.</li>
              <li>커플 연동 시, 서로에게 보낸 메시지를 함께 확인할 수 있어요.</li>
              <li>월 캘린더와 대시보드로 메시지를 주고받은 날짜와 내용을 한눈에 살펴볼 수 있어요.</li>
              <li>알림 시간 설정으로 고마운 마음을 전하는 습관을 만들 수 있어요.</li>
              <li>비밀번호 설정으로 사적인 기록을 안전하게 보호해요.</li>
            </ol>
          </div>
          <p class="text-amber-700 font-semibold text-lg">오늘도, 서로에게 필요한 곰아워 한마디 잊지 마세요.</p>
        </div>
      </section>


      <footer class="border-t border-amber-100 bg-white/50 py-8 mt-8">
        <div class="max-w-4xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div class="flex items-center gap-2">
            <span class="text-xl">🐻</span>
            <span class="font-bold text-gray-800">곰아워</span>
          </div>
          <div class="flex gap-6 text-sm text-gray-600">
            <a href="/support" class="hover:text-amber-600 transition">고객지원</a>
            <a href="/privacy" class="hover:text-amber-600 transition">개인정보처리방침</a>
          </div>
        </div>
        <p class="text-center text-gray-500 text-sm mt-4">© 곰아워</p>
      </footer>
    </div>,
    { title: '곰아워 - 커플 관계 관리 앱' }
  )
})

// /login 공개 페이지 제거: 항상 홈으로 이동
app.get('/login', (c) => c.redirect('/'))

// 로그인 페이지 (앱 전용)
app.get('/app/login', (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const errorMessage = c.req.query('error')
  return c.render(
    <div class="flex items-center justify-center min-h-screen bg-gradient-to-br from-amber-50 to-orange-100 py-12 px-4">
      <div class="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-md">
        <div class="text-center mb-8">
          <div class="inline-flex items-center justify-center w-20 h-20 bg-amber-100 rounded-full mb-6">
            <span class="text-4xl">🐻</span>
          </div>
          <h1 class="text-4xl font-bold text-gray-800 mb-3">로그인</h1>
          <p class="text-gray-600 text-lg">소셜 또는 이메일로 로그인하세요</p>
        </div>
        {errorMessage && (
          <div class="mb-6 p-4 rounded-lg text-sm bg-red-100 text-red-700 border border-red-300 flex items-center">
            <i class="fas fa-exclamation-circle mr-2"></i>
            {errorMessage}
          </div>
        )}
        <div class="space-y-4">
          <a href="/auth/apple/login" class="flex items-center justify-center py-4 px-6 border-2 border-gray-900 rounded-xl bg-black hover:bg-gray-900 transition-all">
            <i class="fab fa-apple text-white text-2xl mr-3"></i>
            <span class="font-semibold text-white">Apple로 계속하기</span>
          </a>
          <a href="/auth/kakao/login" class="flex items-center justify-center py-4 px-6 border-2 border-yellow-400 rounded-xl bg-yellow-400 hover:bg-yellow-500 transition-all">
            <i class="fas fa-comment text-gray-800 text-2xl mr-3"></i>
            <span class="font-semibold text-gray-800">카카오로 계속하기</span>
          </a>
        </div>
        <div class="my-6 flex items-center">
          <div class="flex-1 h-px bg-gray-200"></div>
          <span class="px-3 text-xs text-gray-400">또는 이메일로</span>
          <div class="flex-1 h-px bg-gray-200"></div>
        </div>
        <form method="post" action="/auth/login" class="space-y-4">
          <input type="email" name="email" required placeholder="이메일" class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400" />
          <input type="password" name="password" required placeholder="비밀번호" class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400" />
          <button type="submit" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">로그인</button>
        </form>
        <div class="mt-5 text-center">
          <a href="/signup" class="text-sm text-amber-600 hover:underline font-medium">이메일로 회원가입</a>
        </div>
      </div>
    </div>,
    { title: '로그인 - 곰아워' }
  )
})

// 지원/문의 웹사이트 (App Store Support URL용)
app.get('/support', (c) => {
  const origin = new URL(c.req.url).origin
  return c.render(
    <div class="min-h-screen bg-gradient-to-b from-amber-50 to-white">
      {/* 헤더 */}
      <header class="bg-white/80 backdrop-blur border-b border-amber-100 sticky top-0 z-10">
        <div class="max-w-2xl mx-auto px-4 py-4 flex items-center justify-between">
          <a href={origin} class="flex items-center gap-2">
            <span class="text-2xl">🐻</span>
            <span class="font-bold text-gray-800">곰아워</span>
          </a>
          <nav class="flex gap-4 text-sm">
            <a href={`${origin}/`} class="text-gray-600 hover:text-amber-600 transition">홈</a>
            <a href={`${origin}/support`} class="text-amber-600 font-medium">고객지원</a>
            <a href={`${origin}/privacy`} class="text-gray-600 hover:text-amber-600 transition">개인정보처리방침</a>
          </nav>
        </div>
      </header>

      {/* 히어로 */}
      <section class="max-w-2xl mx-auto px-4 py-16 text-center">
        <h1 class="text-4xl font-bold text-gray-800 mb-4">곰아워 고객지원</h1>
        <p class="text-lg text-gray-600">궁금한 점이 있으시면 언제든 문의해 주세요.</p>
      </section>

      {/* 연락처 정보 (App Store 요구사항) */}
      <section class="max-w-2xl mx-auto px-4 pb-12">
        <div class="bg-white rounded-2xl shadow-lg border border-amber-100 overflow-hidden">
          <div class="p-8">
            <h2 class="text-xl font-bold text-gray-800 mb-4">연락처 정보</h2>
            <p class="text-gray-600 mb-6">앱 이용 문의, 버그 신고, 기능 제안 등 언제든 연락 주세요.</p>
            <div class="space-y-4">
              <div class="flex items-start gap-3">
                <span class="text-amber-500 text-lg">📧</span>
                <div>
                  <p class="font-semibold text-gray-800">이메일</p>
                  <a href="mailto:connected.official.co@gmail.com" class="text-amber-600 hover:underline">
                    connected.official.co@gmail.com
                  </a>
      </div>
              </div>
              <div class="flex items-start gap-3">
                <span class="text-amber-500 text-lg">🏢</span>
                <div>
                  <p class="font-semibold text-gray-800">운영자</p>
                  <p class="text-gray-600">Connected Official Co.</p>
                </div>
              </div>
              <div class="flex items-start gap-3">
                <span class="text-amber-500 text-lg">🔗</span>
                <div>
                  <p class="font-semibold text-gray-800">관련 링크</p>
                  <a href={`${origin}/`} class="block text-amber-600 hover:underline">홈페이지</a>
                  <a href={`${origin}/privacy`} class="block text-amber-600 hover:underline">개인정보처리방침</a>
                </div>
              </div>
            </div>
            <a
              href="mailto:connected.official.co@gmail.com"
              class="inline-flex items-center gap-2 mt-6 px-6 py-3 bg-amber-500 hover:bg-amber-600 text-white font-semibold rounded-xl transition"
            >
              이메일로 문의하기
              <i class="fas fa-external-link-alt text-sm"></i>
            </a>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section class="max-w-2xl mx-auto px-4 pb-16">
        <h2 class="text-xl font-bold text-gray-800 mb-6">자주 묻는 질문</h2>
        <div class="space-y-3">
          <details class="bg-white rounded-xl border border-amber-100 shadow-sm group">
            <summary class="px-6 py-4 cursor-pointer font-medium text-gray-800 list-none flex justify-between items-center">
              계정을 삭제하려면?
              <i class="fas fa-chevron-down text-amber-500 group-open:rotate-180 transition-transform"></i>
            </summary>
            <p class="px-6 pb-4 text-gray-600 text-sm">앱 실행 → 마이페이지 → 계정 삭제에서 바로 삭제할 수 있습니다. 복구가 불가능하니 신중히 진행해 주세요.</p>
          </details>
          <details class="bg-white rounded-xl border border-amber-100 shadow-sm group">
            <summary class="px-6 py-4 cursor-pointer font-medium text-gray-800 list-none flex justify-between items-center">
              비밀번호를 잊어버렸어요
              <i class="fas fa-chevron-down text-amber-500 group-open:rotate-180 transition-transform"></i>
            </summary>
            <p class="px-6 pb-4 text-gray-600 text-sm">이메일 로그인을 사용 중이시면 로그인 화면에서 비밀번호 찾기를 이용해 주세요. 소셜 로그인(카카오, 애플) 사용자는 앱에서 비밀번호 재설정이 필요하지 않습니다.</p>
          </details>
          <details class="bg-white rounded-xl border border-amber-100 shadow-sm group">
            <summary class="px-6 py-4 cursor-pointer font-medium text-gray-800 list-none flex justify-between items-center">
              커플 코드는 어떻게 사용하나요?
              <i class="fas fa-chevron-down text-amber-500 group-open:rotate-180 transition-transform"></i>
            </summary>
            <p class="px-6 pb-4 text-gray-600 text-sm">마이페이지에서 내 커플 코드를 생성한 뒤, 상대방에게 공유하세요. 상대방은 상대방 계정 연동하기 메뉴에서 해당 코드를 입력해 연동할 수 있습니다.</p>
          </details>
          <details class="bg-white rounded-xl border border-amber-100 shadow-sm group">
            <summary class="px-6 py-4 cursor-pointer font-medium text-gray-800 list-none flex justify-between items-center">
              앱 사용 방법이 궁금해요
              <i class="fas fa-chevron-down text-amber-500 group-open:rotate-180 transition-transform"></i>
            </summary>
            <p class="px-6 pb-4 text-gray-600 text-sm">곰아워는 커플이 매일 한 마디씩 기록을 남기는 앱입니다. 회원가입 후 커플과 연동하면 함께 곰아워를 쌓아갈 수 있어요. 더 자세한 안내가 필요하시면 위 이메일로 문의해 주세요.</p>
          </details>
        </div>
      </section>

      {/* 푸터 */}
      <footer class="border-t border-amber-100 bg-white/50 py-8">
        <div class="max-w-2xl mx-auto px-4 text-center text-sm text-gray-500">
          <p class="mb-2">© 곰아워 (gom-hr.com)</p>
          <div class="flex justify-center gap-6">
            <a href={`${origin}/`} class="hover:text-amber-600 transition">홈</a>
            <a href={`${origin}/privacy`} class="hover:text-amber-600 transition">개인정보처리방침</a>
          </div>
        </div>
      </footer>
    </div>,
    { title: '고객지원 - 곰아워' }
  )
})

// 회원가입 페이지 (앱 전용)
app.get('/signup', (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const errorMessage = c.req.query('error')
  return c.render(
    <div class="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div class="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-md">
        <div class="text-center mb-8">
          <h1 class="text-3xl font-bold text-gray-800 mb-3">회원가입</h1>
          <p class="text-gray-600">이메일로 간단히 시작하세요</p>
        </div>
        {errorMessage && (
          <div class="mb-6 p-4 rounded-lg text-sm bg-red-100 text-red-700 border border-red-300">
            <i class="fas fa-exclamation-circle mr-2"></i>
            {errorMessage}
          </div>
        )}
        <form method="post" action="/auth/signup" class="space-y-4">
          <input type="email" name="email" required placeholder="이메일" class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400" />
          <input type="password" name="password" required placeholder="비밀번호 (6-32자)" class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400" />
          <input type="password" name="confirm_password" required placeholder="비밀번호 확인" class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400" />
          <button type="submit" class="w-full py-3 rounded-xl font-bold text-white" style="background: linear-gradient(135deg, #6366F1, #4F46E5);">회원가입</button>
        </form>
        <div class="mt-5 text-center">
          <a href="/app/login" class="text-sm text-indigo-600 hover:underline">이미 계정이 있어요</a>
        </div>
      </div>
    </div>,
    { title: '회원가입 - 곰아워' }
  )
})

// 이메일 회원가입 (닉네임은 설정 페이지에서 입력)
app.post('/auth/signup', async (c) => {
  const body = await c.req.parseBody()
  const rawEmail = String(body.email || '').trim().toLowerCase()
  const password = String(body.password || '')
  const confirmPassword = String(body.confirm_password || '')
  const defaultName = '이메일 사용자'

  if (!rawEmail || !rawEmail.includes('@')) {
    return c.redirect(`/signup?error=${encodeURIComponent('올바른 이메일을 입력해주세요.')}`)
  }
  if (password.length < 6 || password.length > 32) {
    return c.redirect(`/signup?error=${encodeURIComponent('비밀번호는 6-32자여야 합니다.')}`)
  }
  if (password !== confirmPassword) {
    return c.redirect(`/signup?error=${encodeURIComponent('비밀번호가 일치하지 않습니다.')}`)
  }

  try {
    const existing = await c.env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(rawEmail).first()
    if (existing) {
      return c.redirect(`/signup?error=${encodeURIComponent('이미 가입된 이메일입니다.')}`)
    }

    const hashed = await hashPassword(password)
    const result = await c.env.DB.prepare(
      'INSERT INTO users (email, name, password) VALUES (?, ?, ?)'
    ).bind(rawEmail, defaultName, hashed).run()

    const userId = result.meta.last_row_id as number
    const userSession: User = {
      id: rawEmail,
      db_id: userId,
      email: rawEmail,
      name: defaultName,
      provider: 'local',
      couple_id: null,
      couple_code: null,
      gender: undefined,
      notification_time: undefined,
      is_admin: false,
      setup_done: false
    }

    setCookie(c, 'user_session', JSON.stringify(userSession), {
      path: '/',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax',
    })

    return c.redirect('/setup')
  } catch (error) {
    console.error('회원가입 오류:', error)
    return c.redirect(`/signup?error=${encodeURIComponent('회원가입 중 오류가 발생했습니다.')}`)
  }
})

// 이메일 로그인
app.post('/auth/login', async (c) => {
  const body = await c.req.parseBody()
  const rawEmail = String(body.email || '').trim().toLowerCase()
  const password = String(body.password || '')

  if (!rawEmail || !rawEmail.includes('@') || !password) {
    return c.redirect(`/app/login?error=${encodeURIComponent('이메일과 비밀번호를 입력해주세요.')}`)
  }

  try {
    const dbUser = await c.env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(rawEmail).first()

    if (!dbUser || !dbUser.password) {
      return c.redirect(`/app/login?error=${encodeURIComponent('이메일 또는 비밀번호가 올바르지 않습니다.')}`)
    }

    const storedPassword = dbUser.password as string
    const isValid = await verifyPassword(password, storedPassword)
    if (!isValid) {
      return c.redirect(`/app/login?error=${encodeURIComponent('이메일 또는 비밀번호가 올바르지 않습니다.')}`)
    }

    // 레거시(평문) 비밀번호면 해시로 업그레이드
    if (!storedPassword.startsWith('pbkdf2$')) {
      const upgraded = await hashPassword(password)
      await c.env.DB.prepare(
        'UPDATE users SET password = ? WHERE id = ?'
      ).bind(upgraded, dbUser.id).run()
    }

    const coupleCode = await getCoupleCode(c.env.DB, dbUser.couple_id as number | null)
    const isAdminUser = (dbUser.email as string) === 'admin@gomawo.app'
    const setupDone = isAdminUser ? false : !!(dbUser.gender && dbUser.notification_time && dbUser.name && dbUser.name !== 'Apple 사용자' && dbUser.name !== '이메일 사용자')
    const userSession: User = {
      id: rawEmail,
      db_id: dbUser.id as number,
      email: dbUser.email as string,
      name: dbUser.name as string,
      picture: (dbUser.picture as string) || '',
      provider: 'local',
      couple_id: (dbUser.couple_id as number | null) || null,
      couple_code: coupleCode,
      gender: (dbUser.gender as 'male' | 'female' | null) || undefined,
      notification_time: (dbUser.notification_time as string | null) || undefined,
      is_admin: (dbUser.is_admin as number | null) === 1,
      setup_done: setupDone
    }

    setCookie(c, 'user_session', JSON.stringify(userSession), {
      path: '/',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax',
    })

    if ((dbUser.email as string) === 'admin@gomawo.app') {
      setCookie(c, 'admin_force_setup', '1', {
        path: '/',
        httpOnly: true,
        secure: false,
        maxAge: 60 * 10,
        sameSite: 'Lax',
      })
    }

    return c.redirect('/dashboard')
  } catch (error) {
    console.error('로그인 오류:', error)
    return c.redirect(`/app/login?error=${encodeURIComponent('로그인 처리 중 오류가 발생했습니다.')}`)
  }
})

// Apple 로그인 시작
app.get('/auth/apple/login', (c) => {
  const clientId = c.env.APPLE_CLIENT_ID
  const redirectUri = c.env.APPLE_REDIRECT_URI

  if (!clientId || !redirectUri) {
    return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인 설정이 필요합니다.')}`)
  }

  const state = generateOauthState()
  // 쿠키를 gom-hr.com 도메인으로 설정 (apex·www 공유)
  // Apple 콜백은 apex(gom-hr.com)로 오므로, www에서 설정한 쿠키가 전달되려면 domain 필요
  setCookie(c, 'apple_oauth_state', state, {
    path: '/',
    domain: 'gom-hr.com',
    httpOnly: true,
    secure: true,
    maxAge: 60 * 10,
    sameSite: 'None',
  })

  const authUrl = new URL('https://appleid.apple.com/auth/authorize')
  authUrl.searchParams.set('client_id', clientId)
  authUrl.searchParams.set('redirect_uri', redirectUri)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('response_mode', 'form_post')
  authUrl.searchParams.set('scope', 'name email')
  authUrl.searchParams.set('state', state)

  return c.redirect(authUrl.toString())
})

const setFromAppCookie = (c: any) => {
  setCookie(c, 'from_app', '1', {
    path: '/',
    domain: 'gom-hr.com',
    httpOnly: false,
    maxAge: 60 * 60 * 24 * 365,
    sameSite: 'Lax',
  })
}

const handleAppleCallback = async (c: any) => {
  const body = c.req.method === 'POST' ? await c.req.parseBody() : {}
  const error = c.req.query('error') || body.error
  if (error) {
    setFromAppCookie(c)
    return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인이 취소되었습니다.')}`)
  }

  const code = c.req.query('code') || body.code
  const state = c.req.query('state') || body.state
  const stateCookie = getCookie(c, 'apple_oauth_state')

  if (!code || !state || !stateCookie || state !== stateCookie) {
    setFromAppCookie(c)
    return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인 인증에 실패했습니다.')}`)
  }

  try {
    const clientId = c.env.APPLE_CLIENT_ID
    const redirectUri = c.env.APPLE_REDIRECT_URI
    const privateKey = c.env.APPLE_PRIVATE_KEY
    if (!clientId || !redirectUri) {
      setFromAppCookie(c)
      return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인 설정이 필요합니다.')}`)
    }
    if (!privateKey || !privateKey.trim()) {
      setFromAppCookie(c)
      return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인 설정이 필요합니다. (Private Key 미설정)')}`)
    }

    const clientSecret = await createAppleClientSecret(c.env)
    const tokenResponse = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: String(code),
        grant_type: 'authorization_code',
        redirect_uri: redirectUri
      })
    })

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text()
      console.error('Apple token exchange failed:', errorText)
      let appleError = ''
      try {
        const errJson = JSON.parse(errorText) as { error?: string; error_description?: string }
        appleError = errJson.error ? ` (${errJson.error}${errJson.error_description ? ': ' + errJson.error_description : ''})` : ''
      } catch (_) {}
      setFromAppCookie(c)
      return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인에 실패했습니다.' + appleError)}`)
    }

    const tokenData = await tokenResponse.json() as { id_token?: string }
    if (!tokenData.id_token) {
      setFromAppCookie(c)
      return c.redirect(`/app/login?error=${encodeURIComponent('Apple 로그인 정보가 부족합니다.')}`)
    }

    const { payload } = await jwtVerify(tokenData.id_token, appleJwks, {
      issuer: 'https://appleid.apple.com',
      audience: clientId
    })

    const appleId = payload.sub as string
    const email = (payload.email as string | undefined) || `apple_${appleId}@apple.user`
    let userPayload: { name?: { firstName?: string; lastName?: string } } | null = null
    try {
      if (body.user && String(body.user).trim()) userPayload = JSON.parse(String(body.user))
    } catch (_) { /* Apple user 객체 파싱 실패 시 무시 */ }
    const providedName = userPayload?.name
      ? [userPayload.name.lastName, userPayload.name.firstName].filter(Boolean).join(' ')
      : ''
    const emailLocal = email.includes('@') ? email.split('@')[0] : ''
    const isPrivateRelay = email.includes('privaterelay.appleid.com') || email.startsWith('apple_')
    const name = providedName || (!isPrivateRelay && emailLocal ? emailLocal : 'Apple 사용자')

    let existingUser = await c.env.DB.prepare(
      'SELECT * FROM users WHERE apple_id = ?'
    ).bind(appleId).first()

    if (!existingUser) {
      const byEmail = await c.env.DB.prepare(
        'SELECT * FROM users WHERE email = ?'
      ).bind(email).first()
      if (byEmail) {
        existingUser = byEmail
        await c.env.DB.prepare(
          'UPDATE users SET apple_id = ? WHERE id = ?'
        ).bind(appleId, byEmail.id).run()
      }
    }

    let userId: number
    let coupleId: number | null = null
    let coupleCode: string | null = null
    let gender: string | null = null
    let notificationTime = '20:00'
    let isAdmin = false

    if (existingUser) {
      userId = existingUser.id as number
      coupleId = existingUser.couple_id as number | null
      gender = existingUser.gender as string | null
      notificationTime = existingUser.notification_time as string || '20:00'
      isAdmin = (existingUser.is_admin as number | null) === 1

      await c.env.DB.prepare(
        'UPDATE users SET email = ?, name = ? WHERE id = ?'
      ).bind(email, existingUser.name || name, userId).run()

      coupleCode = await getCoupleCode(c.env.DB, coupleId)
    } else {
      const result = await c.env.DB.prepare(
        'INSERT INTO users (apple_id, email, name, picture) VALUES (?, ?, ?, ?)'
      ).bind(appleId, email, name, '').run()
      userId = result.meta.last_row_id as number
    }

    const setupDone = !!(gender && notificationTime && name && name !== 'Apple 사용자' && name !== '이메일 사용자')
    const userSession: User = {
      id: appleId,
      db_id: userId,
      email,
      name: existingUser?.name || name,
      picture: '',
      provider: 'apple',
      couple_id: coupleId,
      couple_code: coupleCode,
      gender,
      notification_time: notificationTime,
      is_admin: isAdmin,
      setup_done: setupDone
    }

    setCookie(c, 'user_session', JSON.stringify(userSession), {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax',
    })
    setFromAppCookie(c)

    return c.redirect('/dashboard')
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error)
    const errName = error instanceof Error ? error.name : 'Error'
    console.error('Apple OAuth error:', errName, errMsg, error instanceof Error ? error.stack : '')
    setFromAppCookie(c)
    return c.redirect(`/app/login?error=${encodeURIComponent('로그인 처리 중 오류가 발생했습니다.')}`)
  }
}

// Apple 로그인 콜백
app.get('/auth/apple/callback', handleAppleCallback)
app.post('/auth/apple/callback', handleAppleCallback)

// App layout: header + bottom nav (for dashboard, history, settings)
const AppLayout = (props: { origin: string; user: User; activeTab: string; children: any }) => {
  const { origin, user, activeTab, children } = props
  return (
    <div class="min-h-screen bg-gradient-to-b from-amber-50 to-white pb-20">
      <header class="bg-white/80 backdrop-blur border-b border-amber-100 sticky top-0 z-10">
        <div class="max-w-2xl mx-auto px-4 py-4 flex items-center justify-between">
          <a href="/dashboard" class="flex items-center gap-2">
            <span class="text-2xl">🐻</span>
            <span class="font-bold text-gray-800">곰아워</span>
          </a>
          <span class="text-sm text-gray-600">{user.name}님</span>
        </div>
      </header>
      <main class="max-w-2xl mx-auto px-4 py-6">
        {children}
      </main>
      <nav class="fixed bottom-0 left-0 right-0 bg-white/90 backdrop-blur border-t border-amber-100 z-10">
        <div class="max-w-2xl mx-auto flex justify-around py-2">
          <a href="/dashboard" class={`flex flex-col items-center py-2 px-4 rounded-lg transition ${activeTab === 'dashboard' ? 'text-amber-600 font-medium' : 'text-gray-500'}`}>
            <i class="fas fa-home text-xl mb-1"></i>
            <span class="text-xs">대시보드</span>
          </a>
          <a href="/history" class={`flex flex-col items-center py-2 px-4 rounded-lg transition ${activeTab === 'history' ? 'text-amber-600 font-medium' : 'text-gray-500'}`}>
            <i class="fas fa-calendar-alt text-xl mb-1"></i>
            <span class="text-xs">기록</span>
          </a>
          <a href="/settings" class={`flex flex-col items-center py-2 px-4 rounded-lg transition ${activeTab === 'settings' ? 'text-amber-600 font-medium' : 'text-gray-500'}`}>
            <i class="fas fa-cog text-xl mb-1"></i>
            <span class="text-xs">설정</span>
            </a>
          </div>
      </nav>
        </div>
  )
}

// 대시보드
app.get('/dashboard', async (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) return c.redirect('/app/login')
  let user: User
  try {
    user = JSON.parse(userSessionCookie)
  } catch {
    return c.redirect('/app/login')
  }
  const origin = new URL(c.req.url).origin
  const today = getTodayKst()
  return c.render(
    <AppLayout origin={origin} user={user} activeTab="dashboard">
      <div class="space-y-6">
        <h1 class="text-xl font-bold text-gray-800">오늘의 곰아워</h1>
        <div class="bg-white rounded-2xl p-6 shadow-lg border border-amber-100">
          <p class="text-sm text-gray-500 mb-2">날짜: {today}</p>
          <textarea id="message-input" rows="4" placeholder="오늘의 한 마디를 남겨보세요" class="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-amber-400 focus:border-amber-400 resize-none"></textarea>
          <button type="button" id="send-btn" class="mt-4 w-full py-3 rounded-xl font-bold text-white shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            <i class="fas fa-paper-plane mr-2"></i>보내기
      </button>
          <p id="message-feedback" class="mt-2 text-sm hidden"></p>
          </div>
        <div class="bg-white rounded-2xl p-6 shadow-md border border-amber-100">
          <h2 class="font-semibold text-gray-800 mb-3">이번 달 기록</h2>
          <div id="month-calendar" class="grid grid-cols-7 gap-1 text-center text-sm">
            {/* filled by inline script */}
          </div>
        </div>
      </div>
      <script dangerouslySetInnerHTML={{ __html: `
        (function() {
          var today = ${JSON.stringify(today)};
          var feedback = document.getElementById('message-feedback');
          var input = document.getElementById('message-input');
          var btn = document.getElementById('send-btn');
          btn.addEventListener('click', function() {
            var content = input.value.trim();
            if (!content) { feedback.textContent = '내용을 입력해주세요.'; feedback.className = 'mt-2 text-sm text-red-600'; feedback.classList.remove('hidden'); return; }
            btn.disabled = true;
            feedback.classList.add('hidden');
            fetch('/api/message/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ content: content, message_date: today })
            }).then(function(r) { return r.json(); }).then(function(res) {
              if (res.success) { feedback.textContent = '저장되었어요 💛'; feedback.className = 'mt-2 text-sm text-green-600'; feedback.classList.remove('hidden'); }
              else { feedback.textContent = res.error || '저장 실패'; feedback.className = 'mt-2 text-sm text-red-600'; feedback.classList.remove('hidden'); }
            }).catch(function() { feedback.textContent = '오류가 발생했습니다.'; feedback.className = 'mt-2 text-sm text-red-600'; feedback.classList.remove('hidden'); })
            .finally(function() { btn.disabled = false; });
          });
          var now = new Date();
          var y = now.getFullYear();
          var m = String(now.getMonth() + 1).padStart(2, '0');
          fetch('/api/messages/' + y + '/' + m, { credentials: 'include' })
            .then(function(r) { return r.json(); })
            .then(function(res) {
              if (!res.success || !res.messages) return;
              var grid = document.getElementById('month-calendar');
              var days = ['일','월','화','수','목','금','토'];
              days.forEach(function(d) { grid.innerHTML += '<span class="text-gray-500 font-medium">' + d + '</span>'; });
              var first = new Date(y, now.getMonth(), 1);
              var start = first.getDay();
              for (var i = 0; i < start; i++) grid.innerHTML += '<span></span>';
              var last = new Date(y, now.getMonth() + 1, 0).getDate();
              for (var d = 1; d <= last; d++) {
                var dd = String(d).padStart(2, '0');
                var key = y + '-' + m + '-' + dd;
                var has = res.messages[key] && (res.messages[key].male || res.messages[key].female);
                grid.innerHTML += '<span class="' + (key === today ? 'text-amber-600 font-bold' : has ? 'text-green-600' : 'text-gray-400') + '">' + d + '</span>';
              }
            });
        })();
      ` }} />
    </AppLayout>,
    { title: '대시보드 - 곰아워' }
  )
})

// 커플 설정 페이지
app.get('/setup', async (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) return c.redirect('/app/login')
  let user: User
  try {
    user = JSON.parse(userSessionCookie)
  } catch {
    return c.redirect('/app/login')
  }
  return c.render(
    <div class="min-h-screen bg-gradient-to-b from-amber-50 to-white">
      <header class="bg-white/80 backdrop-blur border-b border-amber-100 sticky top-0 z-10">
        <div class="max-w-2xl mx-auto px-4 py-4 flex items-center">
          <a href="/dashboard" class="flex items-center gap-2">
            <span class="text-2xl">🐻</span>
            <span class="font-bold text-gray-800">곰아워</span>
          </a>
        </div>
      </header>
      <main class="max-w-2xl mx-auto px-4 py-8">
        <h1 class="text-2xl font-bold text-gray-800 mb-6">커플 설정</h1>
        <p class="text-gray-600 mb-6">닉네임, 성별, 알림 시간을 설정하고 커플과 연동하거나 나중에 하기를 선택하세요.</p>
        <div id="setup-feedback" class="mb-4 p-4 rounded-lg hidden"></div>
        <div class="space-y-4 mb-6">
          <label class="block text-sm font-medium text-gray-700">닉네임</label>
          <input type="text" id="setup-name" placeholder="닉네임" value={user.name && user.name !== 'Apple 사용자' && user.name !== '이메일 사용자' ? user.name : ''} class="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-amber-400" />
          <label class="block text-sm font-medium text-gray-700">성별</label>
          <select id="setup-gender" class="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-amber-400">
            <option value="">선택</option>
            <option value="male" selected={user.gender === 'male'}>남성</option>
            <option value="female" selected={user.gender === 'female'}>여성</option>
          </select>
          <label class="block text-sm font-medium text-gray-700">알림 시간</label>
          <input type="time" id="setup-notification" value={user.notification_time || '20:00'} class="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-amber-400" />
          <label class="block text-sm font-medium text-gray-700">커플 코드 (연동 시 입력)</label>
          <input type="text" id="setup-code" placeholder="6자리 코드 (선택)" class="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-amber-400 uppercase" maxLength={6} />
          </div>
            <div class="space-y-3">
          <button type="button" id="btn-create" class="w-full py-3 rounded-xl font-bold text-white" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            새 커플 만들기
              </button>
          <button type="button" id="btn-join" class="w-full py-3 rounded-xl font-bold text-white bg-gray-700 hover:bg-gray-800">
            코드로 연동하기
              </button>
          <button type="button" id="btn-skip" class="w-full py-3 rounded-xl font-medium text-gray-600 border-2 border-gray-300 hover:bg-gray-50">
            나중에 하기
              </button>
            </div>
      </main>
      <script dangerouslySetInnerHTML={{ __html: `
        (function() {
          var feedback = document.getElementById('setup-feedback');
          function show(msg, isErr) {
            feedback.textContent = msg;
            feedback.className = 'mb-4 p-4 rounded-lg ' + (isErr ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700');
            feedback.classList.remove('hidden');
          }
          function doFetch(url, body) {
            return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify(body) });
          }
          document.getElementById('btn-create').addEventListener('click', function() {
            var name = document.getElementById('setup-name').value.trim();
            var gender = document.getElementById('setup-gender').value;
            var nt = document.getElementById('setup-notification').value || '20:00';
            if (!gender) { show('성별을 선택해주세요.', true); return; }
            doFetch('/api/couple/create', { name: name || undefined, gender: gender, notification_time: nt })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                if (res.success) { show('커플이 생성되었어요! 코드: ' + (res.couple_code || '')); setTimeout(function() { location.href = '/dashboard'; }, 1500); }
                else { show(res.error || '오류', true); }
              }).catch(function() { show('오류가 발생했습니다.', true); });
          });
          document.getElementById('btn-join').addEventListener('click', function() {
            var name = document.getElementById('setup-name').value.trim();
            var gender = document.getElementById('setup-gender').value;
            var nt = document.getElementById('setup-notification').value || '20:00';
            var code = document.getElementById('setup-code').value.trim().toUpperCase();
            if (!gender) { show('성별을 선택해주세요.', true); return; }
            if (!code || code.length !== 6) { show('6자리 커플 코드를 입력해주세요.', true); return; }
            doFetch('/api/couple/join', { name: name || undefined, couple_code: code, gender: gender, notification_time: nt })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                if (res.success) { show('연동되었어요!'); setTimeout(function() { location.href = '/dashboard'; }, 1500); }
                else { show(res.error || '오류', true); }
              }).catch(function() { show('오류가 발생했습니다.', true); });
          });
          document.getElementById('btn-skip').addEventListener('click', function() {
            var name = document.getElementById('setup-name').value.trim();
            var gender = document.getElementById('setup-gender').value;
            var nt = document.getElementById('setup-notification').value || '20:00';
            if (!gender) { show('성별을 선택해주세요.', true); return; }
            doFetch('/api/user/skip-couple-setup', { name: name || undefined, gender: gender, notification_time: nt })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                if (res.success) { show('설정이 저장되었어요.'); setTimeout(function() { location.href = '/dashboard'; }, 1500); }
                else { show(res.error || '오류', true); }
              }).catch(function() { show('오류가 발생했습니다.', true); });
          });
        })();
      ` }} />
    </div>,
    { title: '커플 설정 - 곰아워' }
  )
})

// 기록 보기
app.get('/history', async (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) return c.redirect('/app/login')
  let user: User
  try {
    user = JSON.parse(userSessionCookie)
  } catch {
    return c.redirect('/app/login')
  }
  const origin = new URL(c.req.url).origin
  const now = new Date()
  const year = now.getFullYear()
  const month = now.getMonth()
  return c.render(
    <AppLayout origin={origin} user={user} activeTab="history">
      <div class="space-y-6">
        <h1 class="text-xl font-bold text-gray-800">기록 보기</h1>
        <div class="flex items-center justify-between mb-4">
          <button type="button" id="prev-month" class="p-2 rounded-lg text-amber-600 hover:bg-amber-50">
            <i class="fas fa-chevron-left"></i>
          </button>
          <span id="month-label" class="font-semibold text-gray-800">{year}년 {month + 1}월</span>
          <button type="button" id="next-month" class="p-2 rounded-lg text-amber-600 hover:bg-amber-50">
            <i class="fas fa-chevron-right"></i>
          </button>
        </div>
        <div id="history-calendar" class="grid grid-cols-7 gap-1 text-center text-sm mb-6"></div>
        <div id="day-detail" class="bg-white rounded-2xl p-6 shadow-md border border-amber-100 hidden">
          <h3 id="detail-date" class="font-semibold text-gray-800 mb-3"></h3>
          <div id="detail-content" class="space-y-3"></div>
        </div>
        </div>
      <script dangerouslySetInnerHTML={{ __html: `
        (function() {
          var year = ${year};
          var month = ${month};
          function pad(n) { return String(n).padStart(2, '0'); }
          function load() {
            var y = year;
            var m = month + 1;
            document.getElementById('month-label').textContent = y + '년 ' + m + '월';
            fetch('/api/messages/' + y + '/' + pad(m), { credentials: 'include' })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                var grid = document.getElementById('history-calendar');
                grid.innerHTML = '';
                var days = ['일','월','화','수','목','금','토'];
                days.forEach(function(d) { grid.innerHTML += '<span class="text-gray-500 font-medium">' + d + '</span>'; });
                var first = new Date(year, month, 1);
                var start = first.getDay();
                for (var i = 0; i < start; i++) grid.innerHTML += '<span></span>';
                var last = new Date(year, month + 1, 0).getDate();
                var ms = res.success && res.messages ? res.messages : {};
                for (var d = 1; d <= last; d++) {
                  var dd = pad(d);
                  var key = y + '-' + pad(m) + '-' + dd;
                  var info = ms[key];
                  var has = info && (info.male || info.female);
                  var span = document.createElement('span');
                  span.textContent = d;
                  span.className = has ? 'cursor-pointer text-amber-600 font-medium hover:bg-amber-50 rounded' : 'text-gray-400';
                  span.dataset.date = key;
                  if (has) {
                    span.addEventListener('click', function() {
                      var dt = this.dataset.date;
                      var data = ms[dt];
                      var el = document.getElementById('day-detail');
                      document.getElementById('detail-date').textContent = dt;
                      var cont = document.getElementById('detail-content');
                      cont.innerHTML = '';
                      if (data.male) cont.innerHTML += '<p class="text-gray-700"><strong>' + (data.male.name || '남') + ':</strong> ' + (data.male.content || '') + '</p>';
                      if (data.female) cont.innerHTML += '<p class="text-gray-700"><strong>' + (data.female.name || '여') + ':</strong> ' + (data.female.content || '') + '</p>';
                      el.classList.remove('hidden');
                    });
                  }
                  grid.appendChild(span);
                }
              });
          }
          document.getElementById('prev-month').addEventListener('click', function() {
            if (month === 0) { year--; month = 11; } else month--;
            load();
          });
          document.getElementById('next-month').addEventListener('click', function() {
            if (month === 11) { year++; month = 0; } else month++;
            load();
          });
          load();
        })();
      ` }} />
    </AppLayout>,
    { title: '기록 - 곰아워' }
  )
})

// 설정
app.get('/settings', async (c) => {
  if (!isFromApp(c)) return c.redirect('/')
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) return c.redirect('/app/login')
  let user: User
  try {
    user = JSON.parse(userSessionCookie)
  } catch {
    return c.redirect('/app/login')
  }
  const origin = new URL(c.req.url).origin
  const supportUrl = origin
  return c.render(
    <AppLayout origin={origin} user={user} activeTab="settings">
      <div class="space-y-6">
        <h1 class="text-xl font-bold text-gray-800">설정</h1>
        <div class="bg-white rounded-2xl shadow-md border border-amber-100 overflow-hidden">
          <div class="p-6">
            <h2 class="font-semibold text-gray-800 mb-4">프로필</h2>
            <div class="space-y-3">
              <label class="block text-sm text-gray-600">닉네임</label>
              <div class="flex gap-2">
                <input type="text" id="profile-name" value={user.name} class="flex-1 px-4 py-3 border-2 border-gray-200 rounded-xl" />
                <button type="button" id="save-name" class="px-4 py-3 rounded-xl font-medium text-amber-600 border-2 border-amber-400 hover:bg-amber-50">저장</button>
        </div>
              <p id="name-feedback" class="text-sm hidden"></p>
        </div>
            </div>
          <div class="border-t border-amber-100 p-6">
            <h2 class="font-semibold text-gray-800 mb-2">알림 시간</h2>
            <div class="flex gap-2 items-center">
              <input type="time" id="profile-notification" value={user.notification_time || '20:00'} class="px-4 py-3 border-2 border-gray-200 rounded-xl" />
              <button type="button" id="save-notification" class="px-4 py-3 rounded-xl font-medium text-amber-600 border-2 border-amber-400 hover:bg-amber-50">저장</button>
          </div>
        </div>
            </div>
        <div class="bg-white rounded-2xl shadow-md border border-amber-100 p-6">
          <h2 class="font-semibold text-gray-800 mb-4">커플 연동</h2>
          {user.couple_code ? (
            <div>
              <p class="text-gray-600 text-sm mb-2">커플 코드: <strong class="text-amber-600">{user.couple_code}</strong></p>
              <button type="button" id="copy-code" class="text-sm text-amber-600 hover:underline">코드 복사</button>
              <button type="button" id="unlink-couple" class="block mt-3 text-sm text-red-600 hover:underline">연동 해제</button>
          </div>
          ) : (
            <a href="/setup" class="text-amber-600 hover:underline">커플 연동하기</a>
          )}
        </div>
        <div class="bg-white rounded-2xl shadow-md border border-amber-100 p-6">
          <h2 class="font-semibold text-gray-800 mb-4">고객지원</h2>
          <a href={supportUrl} class="text-amber-600 hover:underline flex items-center gap-2">
            <i class="fas fa-external-link-alt"></i>
            고객지원 페이지
          </a>
            </div>
        <div class="bg-white rounded-2xl shadow-md border border-amber-100 p-6">
          <h2 class="font-semibold text-gray-800 mb-4 text-red-600">계정 삭제</h2>
          <p class="text-sm text-gray-600 mb-3">계정을 삭제하면 모든 데이터가 영구적으로 삭제됩니다.</p>
          <button type="button" id="delete-account" class="px-4 py-2 rounded-lg bg-red-100 text-red-700 hover:bg-red-200 font-medium">
            계정 삭제
          </button>
            </div>
            </div>
      <script dangerouslySetInnerHTML={{ __html: `
        (function() {
          document.getElementById('save-name').addEventListener('click', function() {
            var name = document.getElementById('profile-name').value.trim();
            if (!name) return;
            fetch('/api/user/update-name', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ name: name }) })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                var fb = document.getElementById('name-feedback');
                fb.textContent = res.success ? '저장되었어요.' : (res.error || '저장 실패');
                fb.className = 'text-sm ' + (res.success ? 'text-green-600' : 'text-red-600');
                fb.classList.remove('hidden');
              });
          });
          document.getElementById('save-notification').addEventListener('click', function() {
            var nt = document.getElementById('profile-notification').value;
            fetch('/api/user/update-notification', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ notification_time: nt }) })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                if (res.success) alert('저장되었어요.');
                else alert(res.error || '저장 실패');
              });
          });
          var copyBtn = document.getElementById('copy-code');
          if (copyBtn) {
            copyBtn.addEventListener('click', function() {
              var code = ${JSON.stringify(user.couple_code || '')};
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(code).then(function() { alert('코드가 복사되었어요.'); });
              } else { var inp = document.createElement('input'); inp.value = code; document.body.appendChild(inp); inp.select(); document.execCommand('copy'); document.body.removeChild(inp); alert('코드가 복사되었어요.'); }
            });
          }
          var unlinkBtn = document.getElementById('unlink-couple');
          if (unlinkBtn) {
            unlinkBtn.addEventListener('click', function() {
              if (!confirm('커플 연동을 해제할까요?')) return;
              fetch('/api/couple/unlink', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: '{}' })
                .then(function(r) { return r.json(); })
                .then(function(res) { if (res.success) location.reload(); else alert(res.error || '해제 실패'); });
            });
          }
          document.getElementById('delete-account').addEventListener('click', function() {
            if (!confirm('정말 계정을 삭제할까요?')) return;
            fetch('/api/user/delete-account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: '{}' })
              .then(function(r) { return r.json(); })
              .then(function(res) {
                if (res.success) location.href = '/';
                else alert(res.error || '삭제 실패');
              });
          });
        })();
      ` }} />
    </AppLayout>,
    { title: '설정 - 곰아워' }
  )
})

app.get('/api/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// 커플 코드 생성 API
app.post('/api/couple/create', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { gender, notification_time, name } = await c.req.json()

  // 커플 코드 생성 (6자리 영문 대문자)
  const coupleCode = Math.random().toString(36).substring(2, 8).toUpperCase()

  try {
    // 커플 생성
    const coupleResult = await c.env.DB.prepare(
      'INSERT INTO couples (couple_code) VALUES (?)'
    ).bind(coupleCode).run()

    const coupleId = coupleResult.meta.last_row_id as number

    // 사용자 정보 업데이트
    const linkedAt = formatLocalDate(new Date())
    await c.env.DB.prepare(
      'UPDATE users SET couple_id = ?, gender = ?, notification_time = ?, name = ?, couple_linked_at = ? WHERE id = ?'
    ).bind(coupleId, gender, notification_time, name?.trim() || user.name, linkedAt, user.db_id).run()

    // 세션 업데이트
    user.couple_id = coupleId
    user.couple_code = coupleCode
    user.gender = gender
    user.notification_time = notification_time
    if (name?.trim()) {
      user.name = name.trim()
    }
    user.setup_done = true
    
    setCookie(c, 'user_session', JSON.stringify(user), {
      path: '/',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax',
    })

    return c.json({ success: true, couple_code: coupleCode })
  } catch (error) {
    console.error('커플 생성 오류:', error)
    return c.json({ success: false, error: '커플 생성 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 코드로 연동 API
app.post('/api/couple/join', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { couple_code, gender, notification_time, name } = await c.req.json()

  try {
    // 커플 코드로 커플 찾기
    const couple = await c.env.DB.prepare(
      'SELECT * FROM couples WHERE couple_code = ?'
    ).bind(couple_code).first()

    if (!couple) {
      return c.json({ success: false, error: '존재하지 않는 커플 코드입니다.' }, 404)
    }

    const coupleId = couple.id as number

    // 이미 두 명이 연동되어 있는지 확인
    const existingUsers = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM users WHERE couple_id = ?'
    ).bind(coupleId).first()

    if (existingUsers && (existingUsers.count as number) >= 2) {
      return c.json({ success: false, error: '이미 두 명이 연동된 커플입니다.' }, 400)
    }

    // 사용자 정보 업데이트
    const linkedAt = formatLocalDate(new Date())
    await c.env.DB.prepare(
      'UPDATE users SET couple_id = ?, gender = ?, notification_time = ?, name = ?, couple_linked_at = ? WHERE id = ?'
    ).bind(coupleId, gender, notification_time, name?.trim() || user.name, linkedAt, user.db_id).run()

    // 세션 업데이트
    user.couple_id = coupleId
    user.couple_code = couple_code
    user.gender = gender
    user.notification_time = notification_time
    if (name?.trim()) {
      user.name = name.trim()
    }
    user.setup_done = true
    
    setCookie(c, 'user_session', JSON.stringify(user), {
      path: '/',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax',
    })

    return c.json({ success: true })
  } catch (error) {
    console.error('커플 연동 오류:', error)
    return c.json({ success: false, error: '커플 연동 중 오류가 발생했습니다.' }, 500)
  }
})

// 메시지 저장 API
app.post('/api/message/send', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  
  const effectiveCoupleId = user.couple_id ?? -user.db_id

  const { content, message_date } = await c.req.json()

  try {
    // 오늘 이미 메시지를 보냈는지 확인
    const existingMessage = await c.env.DB.prepare(
      'SELECT * FROM messages WHERE user_id = ? AND message_date = ? AND couple_id = ?'
    ).bind(user.db_id, message_date, effectiveCoupleId).first()

    if (existingMessage) {
      // 기존 메시지 업데이트
      await c.env.DB.prepare(
        'UPDATE messages SET content = ? WHERE id = ?'
      ).bind(content, existingMessage.id).run()
    } else {
      // 새 메시지 삽입
      await c.env.DB.prepare(
        'INSERT INTO messages (user_id, couple_id, content, message_date) VALUES (?, ?, ?, ?)'
      ).bind(user.db_id, effectiveCoupleId, content, message_date).run()
    }

    // 커플 연동 상태면 상대방에게 푸시 전송
    if (user.couple_id) {
      const partner = await c.env.DB.prepare(
        'SELECT id FROM users WHERE couple_id = ? AND id != ? LIMIT 1'
      ).bind(user.couple_id, user.db_id).first()

      if (partner?.id) {
        const tokens = await c.env.DB.prepare(
          'SELECT token FROM device_tokens WHERE user_id = ?'
        ).bind(partner.id).all()

        const message = `${user.name}님이 곰아워했어요🧡`
        for (const tokenRow of tokens.results as any[]) {
          const response = await sendApns(c.env, tokenRow.token, message)
          if (!response.ok) {
            const errorText = await response.text()
            console.error('APNs 전송 실패:', response.status, errorText)
          }
        }
      }
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('메시지 저장 오류:', error)
    return c.json({ success: false, error: '메시지 저장 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플의 메시지 조회 API (특정 월)
app.get('/api/messages/:year/:month', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  
  const effectiveCoupleId = user.couple_id ?? -user.db_id

  const year = c.req.param('year')
  const month = c.req.param('month')
  let startDate = `${year}-${month.padStart(2, '0')}-01`
  const endDate = `${year}-${month.padStart(2, '0')}-31`

  if (user.couple_id) {
    const cutoff = await c.env.DB.prepare(
      'SELECT MAX(couple_linked_at) as cutoff FROM users WHERE couple_id = ? AND couple_linked_at IS NOT NULL'
    ).bind(user.couple_id).first()
    const cutoffDate = cutoff?.cutoff as string | undefined
    if (cutoffDate) {
      if (cutoffDate > endDate) {
        return c.json({ success: true, messages: {} })
      }
      if (cutoffDate > startDate) {
        startDate = cutoffDate
      }
    }
  }

  try {
    // 해당 월의 모든 메시지 조회
    const messages = await c.env.DB.prepare(
      `SELECT m.*, u.gender, u.name 
       FROM messages m 
       JOIN users u ON m.user_id = u.id 
       WHERE m.couple_id = ? AND m.message_date >= ? AND m.message_date <= ?
       ORDER BY m.message_date, m.user_id`
    ).bind(effectiveCoupleId, startDate, endDate).all()

    // 날짜별로 그룹화
    const messagesByDate: Record<string, any> = {}
    
    messages.results.forEach((msg: any) => {
      const date = msg.message_date
      if (!messagesByDate[date]) {
        messagesByDate[date] = { male: null, female: null }
      }
      if (msg.gender === 'male') {
        messagesByDate[date].male = { content: msg.content, id: msg.id, name: msg.name }
      } else if (msg.gender === 'female') {
        messagesByDate[date].female = { content: msg.content, id: msg.id, name: msg.name }
      }
    })

    return c.json({ success: true, messages: messagesByDate })
  } catch (error) {
    console.error('메시지 조회 오류:', error)
    return c.json({ success: false, error: '메시지 조회 중 오류가 발생했습니다.' }, 500)
  }
})

// 사용자 닉네임 업데이트
app.post('/api/user/update-name', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { name } = await c.req.json()

  if (!name || name.trim().length === 0) {
    return c.json({ success: false, error: '닉네임을 입력해주세요.' }, 400)
  }

  try {
    await c.env.DB.prepare(
      'UPDATE users SET name = ? WHERE id = ?'
    ).bind(name.trim(), user.db_id).run()

    // 세션 쿠키 업데이트
    user.name = name.trim()
    setCookie(c, 'user_session', JSON.stringify(user), {
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax'
    })

    return c.json({ success: true })
  } catch (error) {
    console.error('닉네임 업데이트 오류:', error)
    return c.json({ success: false, error: '닉네임 업데이트 중 오류가 발생했습니다.' }, 500)
  }
})

// 사용자 알림 시간 업데이트
app.post('/api/user/update-notification', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { notification_time } = await c.req.json()

  if (!notification_time) {
    return c.json({ success: false, error: '알림 시간을 입력해주세요.' }, 400)
  }

  try {
    await c.env.DB.prepare(
      'UPDATE users SET notification_time = ? WHERE id = ?'
    ).bind(notification_time, user.db_id).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('알림 시간 업데이트 오류:', error)
    return c.json({ success: false, error: '알림 시간 업데이트 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 설정 건너뛰기 (나중에 하기)
app.post('/api/user/skip-couple-setup', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { gender, notification_time, name } = await c.req.json()

  if (!gender) {
    return c.json({ success: false, error: '성별을 선택해주세요.' }, 400)
  }

  try {
    // 성별과 알림 시간만 저장 (커플 연동은 나중에)
    await c.env.DB.prepare(
      'UPDATE users SET gender = ?, notification_time = ?, name = ? WHERE id = ?'
    ).bind(gender, notification_time || '20:00', name?.trim() || user.name, user.db_id).run()

    user.gender = gender
    user.notification_time = notification_time || '20:00'
    if (name?.trim()) {
      user.name = name.trim()
    }
    user.setup_done = true
    setCookie(c, 'user_session', JSON.stringify(user), {
      path: '/',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax'
    })

    return c.json({ success: true })
  } catch (error) {
    console.error('설정 저장 오류:', error)
    return c.json({ success: false, error: '설정 저장 중 오류가 발생했습니다.' }, 500)
  }
})

// 사용자 비밀번호 업데이트
app.post('/api/user/update-password', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { password } = await c.req.json()

  if (!password || !/^\d{4}$/.test(password)) {
    return c.json({ success: false, error: '비밀번호는 4자리 숫자여야 합니다.' }, 400)
  }

  try {
    const hashed = await hashPassword(password)
    await c.env.DB.prepare(
      'UPDATE users SET pin = ? WHERE id = ?'
    ).bind(hashed, user.db_id).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('비밀번호 업데이트 오류:', error)
    return c.json({ success: false, error: '비밀번호 업데이트 중 오류가 발생했습니다.' }, 500)
  }
})

// 앱 잠금 PIN 확인
app.post('/api/user/verify-pin', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { pin } = await c.req.json()

  if (!pin || !/^\d{4}$/.test(pin)) {
    return c.json({ success: false, error: '비밀번호는 4자리 숫자여야 합니다.' }, 400)
  }

  try {
    const row = await c.env.DB.prepare(
      'SELECT pin FROM users WHERE id = ?'
    ).bind(user.db_id).first()

    const stored = row?.pin as string | undefined
    if (!stored) {
      return c.json({ success: false, error: '비밀번호가 설정되지 않았습니다.' }, 400)
    }

    const ok = await verifyPassword(pin, stored)
    return c.json({ success: ok })
  } catch (error) {
    console.error('PIN 확인 오류:', error)
    return c.json({ success: false, error: 'PIN 확인 중 오류가 발생했습니다.' }, 500)
  }
})

// 푸시 토큰 등록 (iOS APNs)
app.post('/api/push/register', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { token } = await c.req.json()

  if (!token || typeof token !== 'string') {
    return c.json({ success: false, error: '유효한 토큰이 필요합니다.' }, 400)
  }

  try {
    await c.env.DB.prepare(
      `INSERT INTO device_tokens (user_id, token, platform)
       VALUES (?, ?, 'ios')
       ON CONFLICT(token) DO UPDATE SET user_id = excluded.user_id`
    ).bind(user.db_id, token).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('푸시 토큰 저장 오류:', error)
    return c.json({ success: false, error: '토큰 저장에 실패했습니다.' }, 500)
  }
})

// 제안/문의 이메일 전송
app.post('/api/feedback', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { subject, message } = await c.req.json()

  if (!subject || !message) {
    return c.json({ success: false, error: '제목과 내용을 모두 입력해주세요.' }, 400)
  }

  const resendApiKey = c.env.RESEND_API_KEY
  const resendFrom = c.env.RESEND_FROM
  const feedbackTo = c.env.FEEDBACK_TO || 'connected.official.co@gmail.com'

  if (!resendApiKey || !resendFrom) {
    const missing = [
      !resendApiKey ? 'RESEND_API_KEY' : null,
      !resendFrom ? 'RESEND_FROM' : null,
    ].filter(Boolean)
    console.error('메일 설정 누락:', missing.join(', '))
    return c.json({ success: false, error: `메일 설정 누락: ${missing.join(', ')}` }, 500)
  }

  const emailText = [
    `제목: ${subject}`,
    '',
    '내용:',
    message,
    '',
    '---',
    `보낸 사람: ${user.name}`,
    `이메일: ${user.email}`,
  ].join('\n')

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: resendFrom,
      to: [feedbackTo],
      subject: `[곰아워] ${subject}`,
      text: emailText,
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    console.error('메일 전송 실패:', errorText)
    return c.json({ success: false, error: '메일 전송에 실패했습니다.' }, 500)
  }

  return c.json({ success: true })
})

// 커플 연동 해제
app.post('/api/couple/unlink', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)

  try {
    // 사용자의 couple_id를 NULL로 설정
    await c.env.DB.prepare(
      'UPDATE users SET couple_id = NULL WHERE id = ?'
    ).bind(user.db_id).run()

    // 세션 쿠키 업데이트
    user.couple_id = undefined
    user.couple_code = undefined
    setCookie(c, 'user_session', JSON.stringify(user), {
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
      sameSite: 'Lax'
    })

    return c.json({ success: true })
  } catch (error) {
    console.error('커플 연동 해제 오류:', error)
    return c.json({ success: false, error: '커플 연동 해제 중 오류가 발생했습니다.' }, 500)
  }
})

// 계정 삭제 API
app.post('/api/user/delete-account', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)

  try {
    const dbUser = await c.env.DB.prepare(
      'SELECT id, couple_id FROM users WHERE id = ?'
    ).bind(user.db_id).first()

    if (!dbUser) {
      deleteCookie(c, 'user_session', { path: '/' })
      return c.json({ success: true })
    }

    const coupleId = dbUser.couple_id as number | null

    if (coupleId) {
      // 상대방 연동 해제
      await c.env.DB.prepare(
        'UPDATE users SET couple_id = NULL WHERE couple_id = ? AND id != ?'
      ).bind(coupleId, user.db_id).run()

      // 커플 메시지 삭제
      await c.env.DB.prepare(
        'DELETE FROM messages WHERE couple_id = ?'
      ).bind(coupleId).run()

      // 커플 삭제
      await c.env.DB.prepare(
        'DELETE FROM couples WHERE id = ?'
      ).bind(coupleId).run()
    }

    // 나의 메시지 삭제 (다른 couple에 있을 경우)
    await c.env.DB.prepare(
      'DELETE FROM messages WHERE user_id = ?'
    ).bind(user.db_id).run()

    // 디바이스 토큰 삭제
    await c.env.DB.prepare(
      'DELETE FROM device_tokens WHERE user_id = ?'
    ).bind(user.db_id).run()

    // 사용자 삭제
    await c.env.DB.prepare(
      'DELETE FROM users WHERE id = ?'
    ).bind(user.db_id).run()

    deleteCookie(c, 'user_session', { path: '/' })

    return c.json({ success: true })
  } catch (error) {
    console.error('계정 삭제 오류:', error)
    return c.json({ success: false, error: '계정 삭제 중 오류가 발생했습니다.' }, 500)
  }
})

// 로그아웃
app.get('/logout', (c) => {
  deleteCookie(c, 'user_session', { path: '/' })
  return c.redirect('/')
})

let cachedApnsToken: { token: string; issuedAt: number } | null = null

const apnsBase64Url = (data: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const apnsTextToBase64Url = (text: string) =>
  btoa(text)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const apnsPemToArrayBuffer = (pem: string) => {
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '')
  const binary = atob(body)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

const createApnsJwt = async (env: Bindings) => {
  const teamId = env.APNS_TEAM_ID
  const keyId = env.APNS_KEY_ID
  const privateKeyPem = env.APNS_PRIVATE_KEY
  if (!teamId || !keyId || !privateKeyPem) {
    throw new Error('APNs 설정이 완료되지 않았습니다.')
  }

  const now = Math.floor(Date.now() / 1000)
  if (cachedApnsToken && now - cachedApnsToken.issuedAt < 50 * 60) {
    return cachedApnsToken.token
  }

  const header = apnsTextToBase64Url(JSON.stringify({ alg: 'ES256', kid: keyId }))
  const payload = apnsTextToBase64Url(JSON.stringify({ iss: teamId, iat: now }))
  const signingInput = `${header}.${payload}`

  const key = await crypto.subtle.importKey(
    'pkcs8',
    apnsPemToArrayBuffer(privateKeyPem),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(signingInput)
  )
  const jwt = `${signingInput}.${apnsBase64Url(signature)}`
  cachedApnsToken = { token: jwt, issuedAt: now }
  return jwt
}

const getKstTime = () => {
  const now = new Date()
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Seoul',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
  return formatter.format(now)
}

const getKstDate = () => {
  const now = new Date()
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Seoul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
  return formatter.format(now)
}

const sendApns = async (env: Bindings, token: string, body: string) => {
  const jwt = await createApnsJwt(env)
  const topic = env.APNS_BUNDLE_ID || 'com.gomhour.gomawo'
  const useSandbox = env.APNS_USE_SANDBOX === 'true'
  const baseUrl = useSandbox ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com'

  return fetch(`${baseUrl}/3/device/${token}`, {
    method: 'POST',
    headers: {
      authorization: `bearer ${jwt}`,
      'apns-topic': topic,
      'apns-push-type': 'alert',
      'apns-priority': '10',
    },
    body: JSON.stringify({
      aps: {
        alert: {
          title: '곰아워',
          body,
        },
        sound: 'default',
      },
    }),
  })
}

const scheduledHandler = async (event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) => {
  try {
    const nowTime = getKstTime()
    const today = getKstDate()

    // 1) 커플 연동된 사용자
    const coupleUsers = await env.DB.prepare(
      `SELECT u.id AS user_id, u.couple_id, u.notification_time, p.name AS partner_name
       FROM users u
       JOIN users p ON p.couple_id = u.couple_id AND p.id != u.id
       WHERE u.couple_id IS NOT NULL AND u.notification_time = ?`
    ).bind(nowTime).all()

    for (const row of (coupleUsers.results || []) as any[]) {
      const tokens = await env.DB.prepare(
        `SELECT token, last_notified_date FROM device_tokens WHERE user_id = ?`
      ).bind(row.user_id).all()

      for (const tokenRow of (tokens.results || []) as any[]) {
        if (tokenRow.last_notified_date === today) continue
        const message = `오늘도 ${row.partner_name}에게 곰아워 한마디, 잊지 말아요💛`
        const response = await sendApns(env, tokenRow.token, message)
        if (response.ok) {
          await env.DB.prepare(
            `UPDATE device_tokens SET last_notified_date = ? WHERE token = ?`
          ).bind(today, tokenRow.token).run()
        } else {
          const errorText = await response.text()
          console.error('APNs 전송 실패:', response.status, errorText)
        }
      }
    }

    // 2) 커플 미연동 사용자(나중에 하기)
    const soloUsers = await env.DB.prepare(
      `SELECT id AS user_id FROM users
       WHERE couple_id IS NULL AND notification_time = ?`
    ).bind(nowTime).all()

    for (const row of (soloUsers.results || []) as any[]) {
      const tokens = await env.DB.prepare(
        `SELECT token, last_notified_date FROM device_tokens WHERE user_id = ?`
      ).bind(row.user_id).all()

      for (const tokenRow of (tokens.results || []) as any[]) {
        if (tokenRow.last_notified_date === today) continue
        const message = `오늘의 곰아워 한마디, 잊지 말아요💛`
        const response = await sendApns(env, tokenRow.token, message)
        if (response.ok) {
          await env.DB.prepare(
            `UPDATE device_tokens SET last_notified_date = ? WHERE token = ?`
          ).bind(today, tokenRow.token).run()
        } else {
          const errorText = await response.text()
          console.error('APNs 전송 실패:', response.status, errorText)
        }
      }
    }
  } catch (error) {
    console.error('스케줄 푸시 오류:', error)
  }
}

export default {
  fetch: app.fetch,
  scheduled: scheduledHandler,
}
