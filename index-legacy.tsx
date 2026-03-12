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

const getCoupleMetDate = async (db: Bindings['DB'], coupleId?: number | null) => {
  if (!coupleId) return null
  const couple = await db.prepare(
    'SELECT met_date FROM couples WHERE id = ?'
  ).bind(coupleId).first()
  return couple?.met_date as string | null
}

// 만난 날: 커플 있으면 couples에서, 없으면 users에서 (테스트용)
const getMetDate = async (db: Bindings['DB'], userId: number, coupleId?: number | null) => {
  if (coupleId) {
    const d = await getCoupleMetDate(db, coupleId)
    if (d) return d
  }
  const user = await db.prepare('SELECT met_date FROM users WHERE id = ?').bind(userId).first()
  return user?.met_date as string | null
}

// 세션 검증: DB에 사용자가 없으면(삭제됨) 쿠키 삭제 후 null 반환
const getValidUserSession = async (c: { env: Bindings } & Parameters<typeof getCookie>[0]): Promise<User | null> => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) return null
  try {
    const user = JSON.parse(userSessionCookie) as User
    const dbUser = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?')
      .bind(user.db_id).first()
    if (!dbUser) {
      deleteCookie(c, 'user_session', { path: '/' })
      return null
    }
    return user
  } catch {
    return null
  }
}

const generateOauthState = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

const normalizeAppleKey = (value?: string) => {
  if (!value) return ''
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value
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

// 소셜 로그인 라우트 등록
app.route('/auth/kakao', kakaoAuth)

// 개인정보처리방침 - /privacy는 /privacy.html로 리다이렉트
app.get('/privacy', (c) => c.redirect('/privacy.html'))

// 렌더러 미들웨어 적용
app.use(renderer)

// 고객지원 페이지 (홈페이지 탭에서 링크)
app.get('/support', (c) => {
  const origin = new URL(c.req.url).origin
  return c.render(
    <div class="min-h-screen bg-gradient-to-b from-amber-50 to-white">
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
      <section class="max-w-2xl mx-auto px-4 py-16 text-center">
        <h1 class="text-4xl font-bold text-gray-800 mb-4">곰아워 고객지원</h1>
        <p class="text-lg text-gray-600">궁금한 점이 있으시면 언제든 문의해 주세요.</p>
      </section>
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

// 로그인 페이지 렌더 (공통)
const renderLoginPage = (errorMessage?: string) => (
  <div class="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
    <div class="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-md">
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full mb-6 shadow-lg">
          <i class="fas fa-rocket text-4xl text-white"></i>
        </div>
        <h1 class="text-4xl font-bold text-gray-800 mb-3">환영합니다!</h1>
        <p class="text-gray-600 text-lg">소셜 또는 이메일로 로그인하세요</p>
      </div>

      {errorMessage && (
        <div class="mb-6 p-4 rounded-lg text-sm bg-red-100 text-red-700 border border-red-300 flex items-center">
          <i class="fas fa-exclamation-circle mr-2"></i>
          {errorMessage}
        </div>
      )}

      <div class="space-y-4">
        <a 
          href="/auth/apple/login"
          class="flex items-center justify-center py-4 px-6 border-2 border-gray-900 rounded-xl bg-black hover:bg-gray-900 transition-all duration-300 hover:shadow-lg transform hover:-translate-y-1 group"
        >
          <i class="fab fa-apple text-white text-2xl mr-3 group-hover:scale-110 transition-transform"></i>
          <span class="text-base font-semibold text-white">Apple로 계속하기</span>
        </a>
        <a 
          href="/auth/kakao/login"
          class="flex items-center justify-center py-4 px-6 border-2 border-yellow-400 rounded-xl bg-yellow-400 hover:bg-yellow-500 transition-all duration-300 hover:shadow-lg transform hover:-translate-y-1 group"
        >
          <i class="fas fa-comment text-gray-800 text-2xl mr-3 group-hover:scale-110 transition-transform"></i>
          <span class="text-base font-semibold text-gray-800">카카오로 계속하기</span>
        </a>
      </div>

      <div class="my-6 flex items-center">
        <div class="flex-1 h-px bg-gray-200"></div>
        <span class="px-3 text-xs text-gray-400">또는 이메일로</span>
        <div class="flex-1 h-px bg-gray-200"></div>
      </div>

      <form method="post" action="/auth/login" class="space-y-4">
        <input
          type="email"
          name="email"
          required
          class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
          placeholder="이메일"
        />
        <input
          type="password"
          name="password"
          required
          class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
          placeholder="비밀번호"
        />
        <button
          type="submit"
          class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all"
          style="background: linear-gradient(135deg, #6366F1, #4F46E5);"
        >
          로그인
        </button>
      </form>

      <div class="mt-5 text-center">
        <a href="/signup" class="text-sm text-indigo-600 hover:underline">이메일로 회원가입</a>
      </div>

      <div class="mt-6 text-center">
        <p class="text-xs text-gray-500">
          로그인하시면 <a href="#" class="text-indigo-600 hover:underline">이용약관</a> 및 
          <a href="#" class="text-indigo-600 hover:underline ml-1">개인정보처리방침</a>에 동의하게 됩니다.
        </p>
      </div>
    </div>
  </div>
)

// 로그인 페이지 (소셜 + 이메일)
app.get('/', (c) => {
  const errorMessage = c.req.query('error')
  return c.render(renderLoginPage(errorMessage), { title: '소셜 로그인 - Web App' })
})

// 앱 로그인 페이지 (/app, /app/login - Flutter WebView 진입점)
app.get('/app', async (c) => {
  const user = await getValidUserSession(c)
  if (user) {
    if (user.setup_done) return c.redirect('/dashboard')
    return c.redirect('/setup')
  }
  return c.redirect('/app/login')
})
app.get('/app/login', (c) => {
  const errorMessage = c.req.query('error')
  return c.render(renderLoginPage(errorMessage), { title: '소셜 로그인 - Web App' })
})

// 회원가입 페이지 (이메일)
app.get('/signup', (c) => {
  const errorMessage = c.req.query('error')

  return c.render(
    <div class="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div class="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-md">
        <div class="text-center mb-8">
          <div class="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full mb-6 shadow-lg">
            <i class="fas fa-user-plus text-4xl text-white"></i>
          </div>
          <h1 class="text-3xl font-bold text-gray-800 mb-3">회원가입</h1>
          <p class="text-gray-600 text-lg">이메일로 간단히 시작하세요</p>
        </div>

        {errorMessage && (
          <div class="mb-6 p-4 rounded-lg text-sm bg-red-100 text-red-700 border border-red-300 flex items-center">
            <i class="fas fa-exclamation-circle mr-2"></i>
            {errorMessage}
          </div>
        )}

        <form method="post" action="/auth/signup" class="space-y-4">
          <input
            type="email"
            name="email"
            required
            class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
            placeholder="이메일"
          />
          <input
            type="password"
            name="password"
            required
            class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
            placeholder="비밀번호 (6-32자)"
          />
          <input
            type="password"
            name="confirm_password"
            required
            class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
            placeholder="비밀번호 확인"
          />
          <button
            type="submit"
            class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all"
            style="background: linear-gradient(135deg, #6366F1, #4F46E5);"
          >
            회원가입
          </button>
        </form>

        <div class="mt-5 text-center">
          <a href="/app/login" class="text-sm text-indigo-600 hover:underline">이미 계정이 있어요</a>
        </div>
      </div>
    </div>,
    { title: '회원가입 - Web App' }
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
      domain: 'gom-hr.com',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })
    setCookie(c, 'from_app', '1', {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })

    return c.redirect('/setup')
  } catch (error) {
    console.error('회원가입 오류:', error)
    return c.redirect(`/signup?error=${encodeURIComponent('회원가입 중 오류가 발생했습니다.')}`)
  }
})

// 이메일 로그인
const loginErrorRedirect = (msg: string) => `/app/login?error=${encodeURIComponent(msg)}`

app.post('/auth/login', async (c) => {
  const body = await c.req.parseBody()
  const rawEmail = String(body.email || '').trim().toLowerCase()
  const password = String(body.password || '')

  if (!rawEmail || !rawEmail.includes('@') || !password) {
    return c.redirect(loginErrorRedirect('이메일과 비밀번호를 입력해주세요.'))
  }

  try {
    const dbUser = await c.env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(rawEmail).first()

    if (!dbUser || !dbUser.password) {
      return c.redirect(loginErrorRedirect('이메일 또는 비밀번호가 올바르지 않습니다.'))
    }

    const storedPassword = dbUser.password as string
    const isValid = await verifyPassword(password, storedPassword)
    if (!isValid) {
      return c.redirect(loginErrorRedirect('이메일 또는 비밀번호가 올바르지 않습니다.'))
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
      domain: 'gom-hr.com',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })
    setCookie(c, 'from_app', '1', {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })

    if ((dbUser.email as string) === 'admin@gomawo.app') {
      setCookie(c, 'admin_force_setup', '1', {
        path: '/',
        domain: 'gom-hr.com',
        httpOnly: true,
        secure: false,
        maxAge: 60 * 10,
        sameSite: 'Lax',
      })
    }

    return c.redirect('/dashboard')
  } catch (error) {
    console.error('로그인 오류:', error)
    return c.redirect(loginErrorRedirect('로그인 처리 중 오류가 발생했습니다.'))
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

const appleErrorRedirect = (msg: string) => `/app/login?error=${encodeURIComponent(msg)}`

const handleAppleCallback = async (c: any) => {
  const body = c.req.method === 'POST' ? await c.req.parseBody() : {}
  const error = c.req.query('error') || body.error
  if (error) {
    return c.redirect(appleErrorRedirect('Apple 로그인이 취소되었습니다.'))
  }

  const code = c.req.query('code') || body.code
  const state = c.req.query('state') || body.state
  const stateCookie = getCookie(c, 'apple_oauth_state')

  if (!code || !state || !stateCookie || state !== stateCookie) {
    return c.redirect(appleErrorRedirect('Apple 로그인 인증에 실패했습니다.'))
  }

  try {
    const clientId = c.env.APPLE_CLIENT_ID
    const redirectUri = c.env.APPLE_REDIRECT_URI
    if (!clientId || !redirectUri) {
      return c.redirect(appleErrorRedirect('Apple 로그인 설정이 필요합니다.'))
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
      return c.redirect(appleErrorRedirect('Apple 로그인에 실패했습니다.'))
    }

    const tokenData = await tokenResponse.json() as { id_token?: string }
    if (!tokenData.id_token) {
      return c.redirect(appleErrorRedirect('Apple 로그인 정보가 부족합니다.'))
    }

    const { payload } = await jwtVerify(tokenData.id_token, appleJwks, {
      issuer: 'https://appleid.apple.com',
      audience: clientId
    })

    const appleId = payload.sub as string
    const email = (payload.email as string | undefined) || `apple_${appleId}@apple.user`
    const userPayload = body.user ? JSON.parse(String(body.user)) : null
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

    const setupDone = !!(gender && notificationTime && name && name !== 'Apple 사용자')
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
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })
    setCookie(c, 'from_app', '1', {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax',
    })

    return c.redirect('/dashboard')
  } catch (error) {
    console.error('Apple OAuth error:', error)
    return c.redirect(appleErrorRedirect('로그인 처리 중 오류가 발생했습니다.'))
  }
}

// Apple 로그인 콜백
app.get('/auth/apple/callback', handleAppleCallback)
app.post('/auth/apple/callback', handleAppleCallback)

// 대시보드 페이지 → 감사 일기 메인 화면으로 변경
app.get('/dashboard', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }

  // DB 기준으로 최신 사용자 정보 확인 (닉네임 포함 - DB가 단일 진실 공급원)
  const dbUser = await c.env.DB.prepare(
    'SELECT name, gender, notification_time, couple_id FROM users WHERE id = ?'
  ).bind(user.db_id).first()

  const effectiveName = (dbUser?.name as string | null) || user.name
  const effectiveGender = (dbUser?.gender as string | null) || user.gender
  const effectiveNotificationTime = (dbUser?.notification_time as string | null) || user.notification_time
  const effectiveCoupleId = (dbUser?.couple_id as number | null) ?? user.couple_id

  // 상대방과 실제 연동됐는지 (커플에 2명 이상일 때만)
  let isPartnerLinked = false
  if (effectiveCoupleId) {
    const coupleCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM users WHERE couple_id = ?'
    ).bind(effectiveCoupleId).first()
    isPartnerLinked = (coupleCount?.count as number) >= 2
  }

  const needsNickname = !effectiveName || effectiveName === 'Apple 사용자' || effectiveName === '이메일 사용자'
  const forceSetupForAdmin = user.email === 'admin@gomawo.app' && getCookie(c, 'admin_force_setup') === '1'

  // 닉네임/성별/알림시간이 설정되지 않았으면 설정 페이지로 리다이렉트
  if (forceSetupForAdmin || needsNickname || !effectiveGender || !effectiveNotificationTime) {
    return c.redirect('/setup')
  }

  const userName = effectiveName || '사용자'
  const userPicture = user?.picture || ''
  const pinRow = await c.env.DB.prepare(
    'SELECT pin FROM users WHERE id = ?'
  ).bind(user.db_id).first()
  const hasPin = !!pinRow?.pin
  let metDate = ''
  try {
    metDate = (await getMetDate(c.env.DB, user.db_id, effectiveCoupleId)) || ''
  } catch { /* met_date 컬럼 없을 수 있음 */ }
  
  return c.render(
    <div class="min-h-screen" style="background: linear-gradient(to bottom, #FFF8E7, #FFE4B5);">
      {/* 상단 헤더 - 서약서 보기 버튼 */}
      <div class="max-w-md mx-auto px-4 pt-6 pb-2 flex justify-end">
        <button id="show-pledge-btn" class="p-2.5 rounded-full bg-white shadow-md hover:shadow-lg transition-all hover:scale-105 text-xl" title="우리 약속 다시 보기">📝</button>
      </div>
      {/* 메인 컨텐츠 */}
      <div class="max-w-md mx-auto px-4 pt-2 pb-6">
          {!isPartnerLinked && (
          <div class="mb-4 p-4 bg-amber-50 border-2 border-amber-200 rounded-2xl">
            <p class="text-sm text-gray-700 mb-3 text-center">
              커플 연동을 하면<br/>
              서로에게 남긴 곰아워 메세지를 같이 볼 수 있어요!
            </p>
            <a href="/settings" class="block text-center px-6 py-2 bg-amber-400 text-white rounded-xl hover:bg-amber-500 transition font-semibold">
              당장 연동하기
            </a>
          </div>
        )}
        {/* 감사 카운터 + 만난 날 */}
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6">
          {metDate && (
            <p class="text-center text-gray-600 text-base mb-3">
              우리가 만난 지 <span class="text-xl font-bold text-amber-600" id="met-days-count">+0</span>일
              <span class="ml-1">💕</span>
            </p>
          )}
          <p class="text-center text-gray-700 text-base">
            이번 달엔 총 <span class="text-3xl font-bold text-amber-600 mx-1" id="gratitude-count">0</span>일 동안 함께 곰아워했어요
            <span class="ml-1">💛</span>
          </p>
        </div>

        {/* 달력 */}
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6">
          <div class="flex items-center justify-between mb-6">
            <button id="prev-month" class="p-2 hover:bg-gray-100 rounded-full transition">
              <i class="fas fa-chevron-left text-gray-600"></i>
            </button>
            <h2 class="text-xl font-bold text-gray-800" id="calendar-title">2026년 2월</h2>
            <button id="next-month" class="p-2 hover:bg-gray-100 rounded-full transition">
              <i class="fas fa-chevron-right text-gray-600"></i>
            </button>
          </div>

          {/* 요일 헤더 */}
          <div class="grid grid-cols-7 gap-2 mb-3">
            <div class="text-center text-xs text-red-500 font-semibold">일</div>
            <div class="text-center text-xs text-gray-600 font-semibold">월</div>
            <div class="text-center text-xs text-gray-600 font-semibold">화</div>
            <div class="text-center text-xs text-gray-600 font-semibold">수</div>
            <div class="text-center text-xs text-gray-600 font-semibold">목</div>
            <div class="text-center text-xs text-gray-600 font-semibold">금</div>
            <div class="text-center text-xs text-blue-500 font-semibold">토</div>
          </div>

          {/* 달력 날짜 */}
          <div id="calendar-days" class="grid grid-cols-7 gap-2">
            {/* JavaScript로 동적 생성 */}
          </div>
        </div>
      </div>

      {/* 하단 네비게이션 */}
      <div class="fixed bottom-0 left-0 right-0 py-4" style="background: linear-gradient(to top, rgba(255,248,231,0.98), rgba(255,228,181,0.95)); padding-bottom: max(1rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-8">
          <div class="flex items-center justify-between">
            <a href="/dashboard" class="flex flex-col items-center space-y-1 text-yellow-400">
              <div class="w-12 h-12 rounded-full bg-yellow-400 flex items-center justify-center shadow-md">
                <i class="fas fa-calendar text-white text-xl"></i>
              </div>
            </a>
            <a href="/history" class="flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-book text-gray-600 text-xl"></i>
              </div>
            </a>
            <a href="/settings" class="flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-user text-gray-600 text-xl"></i>
              </div>
            </a>
          </div>
        </div>
      </div>

      {/* 플로팅 작성 버튼 */}
      <button 
        id="write-button"
        class="fixed bottom-24 right-6 w-16 h-16 rounded-full flex items-center justify-center shadow-2xl transform hover:scale-110 transition-all duration-300"
        style="background: linear-gradient(135deg, #FFD700, #FFA500);"
      >
        <i class="fas fa-envelope text-white text-2xl"></i>
      </button>

      {/* 감사 일기 작성 모달 */}
      <div id="write-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 transform transition-all">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-2xl font-bold text-gray-800">오늘의 고마움을 전해볼까요?</h3>
            <button id="close-modal" class="p-2 hover:bg-gray-100 rounded-full transition">
              <i class="fas fa-times text-gray-600 text-xl"></i>
            </button>
          </div>
          
          <div class="mb-4">
            <textarea 
              id="gratitude-text"
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-2xl focus:ring-2 focus:ring-amber-400 focus:border-transparent transition resize-none"
              rows="6"
              placeholder="예) 오늘 힘든데도 웃게 해줘서 정말 고마웠어 😊"
            ></textarea>
          </div>

          <button 
            id="save-button"
            class="w-full py-4 rounded-2xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all transform hover:scale-105"
            style="background: linear-gradient(135deg, #FFD700, #FFA500);"
          >
            <i class="fas fa-heart mr-2"></i>전달하기
          </button>
        </div>
      </div>

      {/* 날짜별 메시지 보기 모달 */}
      <div id="day-message-modal" class="hidden fixed inset-0 bg-black bg-opacity-40 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-2xl shadow-2xl max-w-md w-full">
          <div class="px-5 pt-4 pb-3 text-center border-b border-gray-200">
            <p class="text-sm text-gray-700 font-semibold" id="day-message-title">날짜</p>
          </div>
          <div id="day-message-body" class="px-5 py-4 space-y-3 text-sm text-gray-800"></div>
          <button id="close-day-message-modal" class="w-full py-3 text-blue-600 font-semibold border-t border-gray-200">
            확인
          </button>
        </div>
      </div>

      {/* 앱 잠금 PIN 모달 */}
      <div id="pin-lock-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
          <div class="text-center mb-4">
            <h3 class="text-xl font-bold text-gray-800">앱 잠금 해제</h3>
            <p class="text-sm text-gray-500 mt-1">4자리 비밀번호를 입력하세요</p>
          </div>
          <div id="pin-lock-dots" class="flex items-center justify-center gap-3 mb-4">
            <span class="w-3 h-3 rounded-full bg-gray-200"></span>
            <span class="w-3 h-3 rounded-full bg-gray-200"></span>
            <span class="w-3 h-3 rounded-full bg-gray-200"></span>
            <span class="w-3 h-3 rounded-full bg-gray-200"></span>
          </div>
          <div class="grid grid-cols-3 gap-3 text-lg font-semibold">
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="1">1</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="2">2</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="3">3</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="4">4</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="5">5</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="6">6</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="7">7</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="8">8</button>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="9">9</button>
            <div></div>
            <button class="pin-lock-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200" data-digit="0">0</button>
            <button id="pin-lock-del" class="py-3 rounded-xl bg-gray-100 hover:bg-gray-200">⌫</button>
          </div>
          <p id="pin-lock-error" class="text-center text-sm text-red-500 mt-3 hidden">비밀번호가 올바르지 않습니다.</p>
        </div>
      </div>

      {/* 곰아워 약속 모달 - 설정 완료 후 첫 메인 진입 시 */}
      <div id="promise-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[60] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 text-center border-4 border-amber-400">
          <img src="/static/promise-bears.png" alt="곰아워" class="w-32 h-32 mx-auto mb-4 object-contain" onerror="this.onerror=null;this.src='/static/bear-couple.png'" />
          <h3 class="text-xl font-bold text-gray-800 mb-2">우리의 약속</h3>
          <p class="text-base text-gray-800 font-semibold mb-6">
            누가 더 자주 했는지보다,<br/>
            함께 마음을 나누고 있다는 게<br/>
            더 소중한 거 아시죠? 🧡
          </p>
          <div class="space-y-4 text-left mb-6">
            <label class="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" id="promise-1" class="w-5 h-5 rounded border-2 border-amber-400 accent-amber-500 focus:ring-amber-400" />
              <span class="text-gray-800">곰아워 횟수로 사랑의 크기 재지 않기</span>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" id="promise-2" class="w-5 h-5 rounded border-2 border-amber-400 accent-amber-500 focus:ring-amber-400" />
              <span class="text-gray-800">내가 더 많이 했다고 삐치지 말기</span>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" id="promise-3" class="w-5 h-5 rounded border-2 border-amber-400 accent-amber-500 focus:ring-amber-400" />
              <span class="text-gray-800">상대가 적게 해도 이해해주기</span>
            </label>
          </div>
          <p class="text-xs text-amber-600 mb-4">세 가지 모두 체크하면 시작할 수 있어요</p>
        </div>
      </div>

      {/* 서약서 다시 보기 모달 - 언제든 귀엽게 볼 수 있어요 */}
      <div id="pledge-view-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[60] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 text-center border-4 border-amber-300">
          <img src="/static/promise-bears.png" alt="곰아워" class="w-28 h-28 mx-auto mb-3 object-contain" onerror="this.onerror=null;this.src='/static/bear-couple.png'" />
          <h3 class="text-xl font-bold text-amber-700 mb-1">우리의 약속</h3>
          <p class="text-base text-gray-800 font-semibold mb-5">
            누가 더 자주 했는지보다,<br/>
            함께 마음을 나누고 있다는 게<br/>
            더 소중한 거 아시죠? 🧡
          </p>
          <div class="space-y-3 text-left mb-6 bg-amber-50 rounded-2xl p-4 border-2 border-amber-100">
            <p class="flex items-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 곰아워 횟수로 사랑의 크기 재지 않기</p>
            <p class="flex items-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 내가 더 많이 했다고 삐치지 말기</p>
            <p class="flex items-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 상대가 적게 해도 이해해주기</p>
          </div>
          <button id="close-pledge-view" class="w-full py-3 rounded-xl font-bold text-white text-base shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            확인했어요!
          </button>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          // 현재 사용자 정보
          const currentUser = ${JSON.stringify(user)};
          const hasPin = ${JSON.stringify(hasPin)};
          const metDate = ${JSON.stringify(metDate)};
          
          // 서약서 다시 보기 버튼
          (function() {
            const showBtn = document.getElementById('show-pledge-btn');
            const pledgeModal = document.getElementById('pledge-view-modal');
            const closeBtn = document.getElementById('close-pledge-view');
            if (showBtn && pledgeModal) {
              showBtn.addEventListener('click', () => pledgeModal.classList.remove('hidden'));
            }
            if (closeBtn && pledgeModal) {
              closeBtn.addEventListener('click', () => pledgeModal.classList.add('hidden'));
            }
            if (pledgeModal) {
              pledgeModal.addEventListener('click', (e) => { if (e.target === pledgeModal) pledgeModal.classList.add('hidden'); });
            }
          })();
          
          // 곰아워 약속 모달 - 설정 완료 후 첫 진입 시 (force=1 또는 from_setup=1이면 무조건 표시)
          (function() {
            const params = new URLSearchParams(window.location.search);
            if (params.get('show_promise') !== '1') return;
            const forceShow = params.get('force') === '1' || params.get('from_setup') === '1';
            if (!forceShow && localStorage.getItem('gomawo_promise_done')) return;
            const modal = document.getElementById('promise-modal');
            const c1 = document.getElementById('promise-1');
            const c2 = document.getElementById('promise-2');
            const c3 = document.getElementById('promise-3');
            if (!modal || !c1 || !c2 || !c3) return;
            modal.classList.remove('hidden');
            function checkAll() {
              if (c1.checked && c2.checked && c3.checked) {
                if (!params.get('force')) localStorage.setItem('gomawo_promise_done', '1');
                modal.classList.add('hidden');
                history.replaceState({}, '', '/dashboard');
              }
            }
            c1.addEventListener('change', checkAll);
            c2.addEventListener('change', checkAll);
            c3.addEventListener('change', checkAll);
          })();
          
          // 만난 날 +N일 계산
          if (metDate && document.getElementById('met-days-count')) {
            const met = new Date(metDate + 'T00:00:00');
            const today = new Date();
            const diffTime = today - met;
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
            document.getElementById('met-days-count').textContent = '+' + (diffDays >= 0 ? diffDays : 0);
          }
          
          // 메시지 데이터 (DB에서 불러옴)
          let messagesData = {};
          let currentDate = new Date();
          let currentYear = currentDate.getFullYear();
          let currentMonth = currentDate.getMonth();

          // 메시지 데이터 불러오기
          async function loadMessages(year, month) {
            try {
              const response = await fetch('/api/messages/' + year + '/' + (month + 1));
              const data = await response.json();
              if (data.success) {
                messagesData = data.messages || {};
                updateCounter();
                renderCalendar(year, month);
              }
            } catch (error) {
              console.error('메시지 로드 실패:', error);
            }
          }

          // 카운터 업데이트 (두 명 모두 보낸 날만 카운트)
          function updateCounter() {
            let togetherCount = 0;
            
            // 두 명 모두 메시지를 보낸 날만 카운트
            Object.keys(messagesData).forEach(date => {
              const dayMessages = messagesData[date];
              if (dayMessages.male && dayMessages.female) {
                togetherCount++;
              }
            });
            
            document.getElementById('gratitude-count').textContent = togetherCount;
          }

          const todayKey = currentDate.getFullYear() + '-' + String(currentDate.getMonth() + 1).padStart(2, '0') + '-' + String(currentDate.getDate()).padStart(2, '0');
          
          // 달력 렌더링
          function renderCalendar(year, month) {
            const firstDay = new Date(year, month, 1).getDay();
            const daysInMonth = new Date(year, month + 1, 0).getDate();
            const calendarDays = document.getElementById('calendar-days');
            const calendarTitle = document.getElementById('calendar-title');
            
            calendarTitle.textContent = year + '년 ' + (month + 1) + '월';
            calendarDays.innerHTML = '';

            // 빈 칸 추가
            for (let i = 0; i < firstDay; i++) {
              calendarDays.innerHTML += '<div></div>';
            }

            // 날짜 추가
            for (let day = 1; day <= daysInMonth; day++) {
              const dateKey = year + '-' + String(month + 1).padStart(2, '0') + '-' + String(day).padStart(2, '0');
              const dayMessages = messagesData[dateKey];
              const isToday = year === currentDate.getFullYear() && month === currentDate.getMonth() && day === currentDate.getDate();
              
              const dayDiv = document.createElement('div');
              dayDiv.className = 'flex flex-col items-center justify-center p-2 cursor-pointer hover:bg-gray-50 rounded-lg transition';
              
              if (isToday) {
                dayDiv.innerHTML = '<div class="text-sm font-bold text-yellow-500">' + day + '</div>';
              } else {
                dayDiv.innerHTML = '<div class="text-sm text-gray-700">' + day + '</div>';
              }
              
              // 곰돌이 표시 로직
              if (dayMessages) {
                const hasMale = dayMessages.male !== null;
                const hasFemale = dayMessages.female !== null;
                const isPast = dateKey < todayKey;
                const showCrying = isPast && ((hasMale && !hasFemale) || (!hasMale && hasFemale));
                
                if (hasMale && hasFemale) {
                  // 두 명 다 보냄: 커플 곰돌이 (하트 들고 있는 두 마리)
                  dayDiv.innerHTML += '<div class="w-16 h-16 flex items-center justify-center mt-1"><img src="/static/bear-couple.png" alt="커플 곰돌이" class="w-full h-full object-contain"></div>';
                } else if (hasMale) {
                  // 남자만 보냄: 자정 전엔 기본, 이후엔 울고 있는 곰돌이
                  const maleImg = showCrying ? '/static/bear-male-cry.png' : '/static/bear-male.png';
                  const maleAlt = showCrying ? '울고 있는 남자 곰돌이' : '남자 곰돌이';
                  dayDiv.innerHTML += '<div class="w-14 h-14 flex items-center justify-center mt-1"><img src="' + maleImg + '" alt="' + maleAlt + '" class="w-full h-full object-contain"></div>';
                } else if (hasFemale) {
                  // 여자만 보냄: 자정 전엔 기본, 이후엔 울고 있는 곰돌이
                  const femaleImg = showCrying ? '/static/bear-female-cry.png' : '/static/bear-female.png';
                  const femaleAlt = showCrying ? '울고 있는 여자 곰돌이' : '여자 곰돌이';
                  dayDiv.innerHTML += '<div class="w-14 h-14 flex items-center justify-center mt-1"><img src="' + femaleImg + '" alt="' + femaleAlt + '" class="w-full h-full object-contain"></div>';
                }
                
                dayDiv.onclick = () => {
                  const titleEl = document.getElementById('day-message-title');
                  const bodyEl = document.getElementById('day-message-body');
                  titleEl.textContent = dateKey;
                  bodyEl.innerHTML = '';

                  if (hasMale && dayMessages.male) {
                    const maleName = dayMessages.male.name || '남자친구';
                    const maleBlock = document.createElement('div');
                    maleBlock.className = 'whitespace-pre-wrap';
                    maleBlock.textContent = maleName + ': ' + dayMessages.male.content;
                    bodyEl.appendChild(maleBlock);
                  }

                  if (hasFemale && dayMessages.female) {
                    const femaleName = dayMessages.female.name || '여자친구';
                    const femaleBlock = document.createElement('div');
                    femaleBlock.className = 'whitespace-pre-wrap';
                    femaleBlock.textContent = femaleName + ': ' + dayMessages.female.content;
                    bodyEl.appendChild(femaleBlock);
                  }

                  document.getElementById('day-message-modal').classList.remove('hidden');
                };
              } else {
                dayDiv.innerHTML += '<div class="w-8 h-8 bg-gray-200 rounded-full mt-1"></div>';
              }
              
              calendarDays.appendChild(dayDiv);
            }
          }

          // 이전/다음 달
          document.getElementById('prev-month').addEventListener('click', () => {
            currentMonth--;
            if (currentMonth < 0) {
              currentMonth = 11;
              currentYear--;
            }
            loadMessages(currentYear, currentMonth);
          });

          document.getElementById('next-month').addEventListener('click', () => {
            currentMonth++;
            if (currentMonth > 11) {
              currentMonth = 0;
              currentYear++;
            }
            loadMessages(currentYear, currentMonth);
          });

          // 모달 열기/닫기
          document.getElementById('write-button').addEventListener('click', () => {
            document.getElementById('write-modal').classList.remove('hidden');
            document.getElementById('gratitude-text').value = '';
          });

          document.getElementById('close-modal').addEventListener('click', () => {
            document.getElementById('write-modal').classList.add('hidden');
          });

          // 앱 잠금 PIN
          if (hasPin && !sessionStorage.getItem('pin_unlocked')) {
            document.getElementById('pin-lock-modal').classList.remove('hidden');
          }

          const pinLockDots = document.querySelectorAll('#pin-lock-dots span');
          let pinLockValue = '';
          function renderPinLockDots() {
            pinLockDots.forEach((dot, idx) => {
              dot.classList.toggle('bg-amber-400', idx < pinLockValue.length);
              dot.classList.toggle('bg-gray-200', idx >= pinLockValue.length);
            });
          }

          document.querySelectorAll('.pin-lock-key').forEach(btn => {
            btn.addEventListener('click', async () => {
              if (pinLockValue.length >= 4) return;
              pinLockValue += btn.dataset.digit;
              renderPinLockDots();
              if (pinLockValue.length === 4) {
                try {
                  const res = await fetch('/api/user/verify-pin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ pin: pinLockValue })
                  });
                  const data = await res.json();
                  if (data.success) {
                    sessionStorage.setItem('pin_unlocked', '1');
                    document.getElementById('pin-lock-modal').classList.add('hidden');
                  } else {
                    document.getElementById('pin-lock-error').classList.remove('hidden');
                    pinLockValue = '';
                    renderPinLockDots();
                  }
                } catch (e) {
                  document.getElementById('pin-lock-error').classList.remove('hidden');
                  pinLockValue = '';
                  renderPinLockDots();
                }
              }
            });
          });

          document.getElementById('pin-lock-del').addEventListener('click', () => {
            if (pinLockValue.length > 0) {
              pinLockValue = pinLockValue.slice(0, -1);
              renderPinLockDots();
            }
          });

          document.getElementById('close-day-message-modal').addEventListener('click', () => {
            document.getElementById('day-message-modal').classList.add('hidden');
          });

          // 전달하기
          document.getElementById('save-button').addEventListener('click', async () => {
            const text = document.getElementById('gratitude-text').value.trim();
            if (!text) {
              alert('따뜻한 한마디를 적어주세요 😊');
              return;
            }

            const today = currentDate.getFullYear() + '-' + 
                         String(currentDate.getMonth() + 1).padStart(2, '0') + '-' + 
                         String(currentDate.getDate()).padStart(2, '0');
            
            try {
              const response = await fetch('/api/message/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                  content: text, 
                  message_date: today 
                })
              });
              
              const data = await response.json();
              if (data.success) {
                document.getElementById('write-modal').classList.add('hidden');
                await loadMessages(currentYear, currentMonth);
                alert('고마운 마음이 잘 전달됐어요 💛');
              } else {
                alert(data.error || '메시지 전달에 실패했습니다.');
              }
            } catch (error) {
              console.error('메시지 전송 오류:', error);
              alert('메시지 전달 중 오류가 발생했습니다.');
            }
          });

          // 초기화
          loadMessages(currentYear, currentMonth);
        `
      }} />
    </div>,
    { title: '감사 일기 - thankyou' }
  )
})

// 커플 설정 페이지
app.get('/setup', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }

  const needsNickname = !user.name || user.name === 'Apple 사용자' || user.name === '이메일 사용자'
  const forceSetupForAdmin = user.email === 'admin@gomawo.app' && getCookie(c, 'admin_force_setup') === '1'

  // 이미 설정을 완료한 사용자인지 확인 (닉네임/성별/알림시간이 있으면 설정 완료)
  if (!forceSetupForAdmin && !needsNickname && user.gender && user.notification_time) {
    return c.redirect('/dashboard')
  }

  if (forceSetupForAdmin) {
    deleteCookie(c, 'admin_force_setup', { path: '/' })
  }

  return c.render(
    <div class="min-h-screen" style="background: linear-gradient(to bottom, #FFF8E7, #FFE4B5);">
      <div class="max-w-md mx-auto px-4 py-8">
        <div class="bg-white rounded-3xl shadow-2xl p-8">
          <div class="text-center mb-8">
            <p class="text-lg font-bold text-gray-800">
              설정을 완료하고,<br/>
              연인과 함께 곰아워 메세지를 나눠보세요<br/>
              🧡💛🤎
            </p>
          </div>

          {/* 닉네임 설정 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">닉네임</label>
            <input 
              type="text" 
              id="nickname-input"
              value={user.email === 'admin@gomawo.app' ? '' : (user.name && user.name !== 'Apple 사용자' && user.name !== '이메일 사용자' ? user.name : '')}
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400 focus:border-transparent"
              placeholder=""
            />
          </div>

          {/* 성별 선택 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">성별</label>
            <div class="grid grid-cols-2 gap-4">
              <button id="gender-male" class="gender-btn py-4 px-6 border-2 border-gray-300 rounded-xl hover:border-blue-400 hover:bg-blue-50 transition-all">
                <div class="mb-2 flex items-center justify-center">
                  <img src="/static/bear-male-face.png" alt="남자" class="w-14 h-14 object-contain" />
                </div>
                <div class="font-semibold">남자</div>
              </button>
              <button id="gender-female" class="gender-btn py-4 px-6 border-2 border-gray-300 rounded-xl hover:border-pink-400 hover:bg-pink-50 transition-all">
                <div class="mb-2 flex items-center justify-center">
                  <img src="/static/bear-female-face.png" alt="여자" class="w-14 h-14 object-contain" />
                </div>
                <div class="font-semibold">여자</div>
              </button>
            </div>
          </div>

          {/* 알림 시간 설정 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">알림 시간</label>
            <div class="relative date-time-input-wrap">
              <div class="form-input-box w-full px-4 py-3 border-2 border-gray-300 rounded-2xl bg-white text-gray-800" id="setup-time-display">오후 8:00</div>
              <input type="time" id="notification-time" value="20:00" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            </div>
            <p class="text-xs text-gray-500 mt-2">매일 이 시간에 메시지 작성 알림을 받아요</p>
          </div>

          {/* 커플 코드 선택 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">커플 연동</label>
            <div class="space-y-3">
              <button id="create-code-btn" class="w-full py-4 px-6 border-2 border-amber-400 rounded-xl bg-amber-50 hover:bg-amber-100 transition-all text-left">
                <div class="flex items-center justify-between">
                  <div>
                    <div class="font-bold text-gray-800">새 커플 코드 생성</div>
                    <div class="text-sm text-gray-600">코드를 만들고 상대방에게 공유</div>
                  </div>
                  <i class="fas fa-plus-circle text-amber-600 text-2xl"></i>
                </div>
              </button>
              
              <button id="join-code-btn" class="w-full py-4 px-6 border-2 border-gray-300 rounded-xl hover:border-blue-400 hover:bg-blue-50 transition-all text-left">
                <div class="flex items-center justify-between">
                  <div>
                    <div class="font-bold text-gray-800">커플 코드 입력</div>
                    <div class="text-sm text-gray-600">상대방이 공유한 코드 입력</div>
                  </div>
                  <i class="fas fa-keyboard text-gray-600 text-2xl"></i>
                </div>
              </button>

              <form id="skip-setup-form" method="post" action="/setup/skip" target="_self" enctype="application/x-www-form-urlencoded" style="display:none">
                <input type="hidden" name="name" id="skip-form-name" value="" />
                <input type="hidden" name="gender" id="skip-form-gender" value="" />
                <input type="hidden" name="notification_time" id="skip-form-time" value="" />
              </form>
              <button type="button" id="skip-setup-btn" class="w-full py-3 px-6 border-2 border-gray-200 rounded-xl hover:border-gray-300 hover:bg-gray-50 transition-all text-center">
                <div class="text-sm text-gray-600">
                  <i class="fas fa-clock mr-2"></i>나중에 연동하기
                </div>
              </button>
            </div>
          </div>

          {/* 커플 코드 생성 영역 */}
          <div id="create-code-area" class="hidden mb-6">
            <div class="bg-gradient-to-br from-amber-100 to-orange-100 rounded-2xl p-6 text-center">
              <p class="text-sm text-gray-700 mb-3">생성된 커플 코드</p>
              <div class="text-3xl font-bold text-amber-600 mb-4" id="generated-code">------</div>
              <button id="copy-code-btn" class="px-6 py-2 bg-white rounded-lg shadow hover:shadow-lg transition-all">
                <i class="fas fa-copy mr-2"></i>코드 복사
              </button>
              <p class="text-xs text-gray-600 mt-4">이 코드를 상대방에게 공유하고<br/>상대방이 입력하면 연동 완료!</p>
              <a href="/dashboard?show_promise=1" class="block mt-4 w-full py-3 rounded-xl font-bold text-white text-base shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
                <i class="fas fa-paw mr-2"></i>곰아워 시작하기
              </a>
            </div>
          </div>

          {/* 커플 코드 입력 영역 */}
          <div id="join-code-area" class="hidden mb-6">
            <input 
              type="text" 
              id="couple-code-input"
              placeholder="커플 코드를 입력하세요"
              maxlength="6"
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-center text-2xl font-bold uppercase mb-4"
            />
            <button id="join-couple-btn" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-heart mr-2"></i>연동하기
            </button>
          </div>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          let selectedGender = null;
          
          const setupTimeDisplay = document.getElementById('setup-time-display');
          const setupTimeInput = document.getElementById('notification-time');
          const fmtSetupTime = (v) => { if (!v) return '20:00'; const [h,m]=v.split(':'); const hh=+h; return hh>=12 ? '오후 '+(hh===12?12:hh-12)+':'+(m||'00') : '오전 '+(hh||12)+':'+(m||'00'); };
          if (setupTimeDisplay && setupTimeInput) {
            setupTimeInput.addEventListener('input', () => { setupTimeDisplay.textContent = fmtSetupTime(setupTimeInput.value); });
            setupTimeInput.addEventListener('change', () => { setupTimeDisplay.textContent = fmtSetupTime(setupTimeInput.value); });
          }

          // 성별 선택
          document.querySelectorAll('.gender-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
              document.querySelectorAll('.gender-btn').forEach(b => {
                b.classList.remove('border-4', 'border-amber-500', 'bg-amber-50');
                b.classList.add('border-2', 'border-gray-300');
              });
              e.currentTarget.classList.remove('border-2', 'border-gray-300');
              e.currentTarget.classList.add('border-4', 'border-amber-500', 'bg-amber-50');
              selectedGender = e.currentTarget.id === 'gender-male' ? 'male' : 'female';
            });
          });
          
          // 새 커플 코드 생성
          document.getElementById('create-code-btn').addEventListener('click', async () => {
            const nickname = document.getElementById('nickname-input').value.trim();
            if (!nickname) {
              alert('닉네임을 입력해주세요!');
              return;
            }
            if (!selectedGender) {
              alert('성별을 먼저 선택해주세요!');
              return;
            }
            
            const notificationTime = document.getElementById('notification-time').value;
            
            const response = await fetch('/api/couple/create', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ name: nickname || undefined, gender: selectedGender, notification_time: notificationTime })
            });
            
            const data = await response.json();
            if (data.success) {
              document.getElementById('generated-code').textContent = data.couple_code;
              document.getElementById('create-code-area').classList.remove('hidden');
              document.getElementById('join-code-area').classList.add('hidden');
            } else {
              alert(data.error || '커플 코드 생성에 실패했습니다.');
            }
          });
          
          // 커플 코드 입력
          document.getElementById('join-code-btn').addEventListener('click', () => {
            document.getElementById('join-code-area').classList.remove('hidden');
            document.getElementById('create-code-area').classList.add('hidden');
          });
          
          // 커플 코드 복사
          document.getElementById('copy-code-btn').addEventListener('click', () => {
            const code = document.getElementById('generated-code').textContent;
            navigator.clipboard.writeText(code);
            alert('커플 코드가 복사되었어요! 상대방에게 공유해주세요 💕');
          });
          
          // 커플 연동
          document.getElementById('join-couple-btn').addEventListener('click', async () => {
            const nickname = document.getElementById('nickname-input').value.trim();
            if (!nickname) {
              alert('닉네임을 입력해주세요!');
              return;
            }
            if (!selectedGender) {
              alert('성별을 먼저 선택해주세요!');
              return;
            }
            
            const coupleCode = document.getElementById('couple-code-input').value.trim().toUpperCase();
            if (!coupleCode || coupleCode.length !== 6) {
              alert('올바른 커플 코드를 입력해주세요!');
              return;
            }
            
            const notificationTime = document.getElementById('notification-time').value;
            
            const response = await fetch('/api/couple/join', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ 
                couple_code: coupleCode, 
                name: nickname || undefined,
                gender: selectedGender,
                notification_time: notificationTime
              })
            });
            
            const data = await response.json();
            if (data.success) {
              alert('커플 연동이 완료되었어요! 💕');
              const target = (window.location.origin || '') + '/dashboard?show_promise=1';
              window.location.replace(target);
            } else {
              alert(data.error || '커플 연동에 실패했습니다.');
            }
          });

          // 나중에 하기 버튼 - fetch 우선, 실패 시 폼 제출 (WebView 호환)
          document.getElementById('skip-setup-btn').addEventListener('click', async function() {
            const nickname = document.getElementById('nickname-input').value.trim();
            if (!nickname) {
              alert('닉네임을 입력해주세요!');
              return;
            }
            if (!selectedGender) {
              alert('성별을 먼저 선택해주세요!');
              return;
            }
            const notificationTime = document.getElementById('notification-time').value || '20:00';
            const btn = this;
            btn.disabled = true;
            btn.innerHTML = '<div class="text-sm text-gray-500"><i class="fas fa-spinner fa-spin mr-2"></i>처리 중...</div>';
            try {
              const res = await fetch('/setup/skip', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ name: nickname || '', gender: selectedGender, notification_time: notificationTime }).toString(),
                redirect: 'follow'
              });
              if (res.redirected && res.url) {
                window.location.replace(res.url);
                return;
              }
              if (res.ok) {
                window.location.replace('/dashboard?show_promise=1&from_setup=1');
                return;
              }
            } catch (e) {}
            document.getElementById('skip-form-name').value = nickname;
            document.getElementById('skip-form-gender').value = selectedGender;
            document.getElementById('skip-form-time').value = notificationTime;
            document.getElementById('skip-setup-form').submit();
          });
        `
      }} />
    </div>,
    { title: '커플 설정 - 곰아워' }
  )
})

// 메시지 히스토리 페이지
app.get('/history', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }

  // 성별이나 알림시간이 설정되지 않았으면 설정 페이지로 리다이렉트
  if (!user.gender || !user.notification_time) {
    return c.redirect('/setup')
  }

  // 커플 연동이 안 되어 있어도 접근 가능
  // if (!user.couple_id) {
  //   return c.redirect('/setup')
  // }

  return c.render(
    <div class="min-h-screen pb-24" style="background: linear-gradient(to bottom, #FFF8E7, #FFE4B5);">
      <div class="max-w-md mx-auto px-4 py-6">
        {/* 헤더 */}
        <div class="flex items-center justify-center mb-6">
          <img src="/static/bear-title.png" alt="곰아워" class="w-12 h-12 mr-3 object-contain" />
          <h1 class="text-2xl font-bold text-gray-800">
            우리의 곰아워 메세지들
          </h1>
        </div>

        {/* 년도/월 선택 */}
        <div class="flex items-center justify-center gap-4 mb-6">
          <select id="year-select" class="px-4 py-2 border-2 border-gray-300 rounded-xl bg-white focus:ring-2 focus:ring-amber-400 focus:border-transparent">
            <option value="2024">2024년</option>
            <option value="2025">2025년</option>
            <option value="2026" selected>2026년</option>
          </select>
          <select id="month-select" class="px-4 py-2 border-2 border-gray-300 rounded-xl bg-white focus:ring-2 focus:ring-amber-400 focus:border-transparent">
            <option value="1">1월</option>
            <option value="2" selected>2월</option>
            <option value="3">3월</option>
            <option value="4">4월</option>
            <option value="5">5월</option>
            <option value="6">6월</option>
            <option value="7">7월</option>
            <option value="8">8월</option>
            <option value="9">9월</option>
            <option value="10">10월</option>
            <option value="11">11월</option>
            <option value="12">12월</option>
          </select>
        </div>

        {/* 메시지 리스트 */}
        <div id="messages-list" class="space-y-4">
          {/* JavaScript로 동적 생성 */}
        </div>

        {/* 메시지가 없을 때 */}
        <div id="no-messages" class="hidden text-center py-12">
          <div class="text-6xl mb-4">📭</div>
          <p class="text-gray-600">아직 메시지가 없어요</p>
          <p class="text-sm text-gray-500 mt-2">메시지를 작성해서 전달해보세요!</p>
        </div>
      </div>

      {/* 하단 네비게이션 */}
      <div class="fixed bottom-0 left-0 right-0 py-4" style="background: linear-gradient(to top, rgba(255,248,231,0.98), rgba(255,228,181,0.95)); padding-bottom: max(1rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-8">
          <div class="flex items-center justify-between">
            <a href="/dashboard" class="flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-calendar text-gray-600 text-xl"></i>
              </div>
            </a>
            <a href="/history" class="flex flex-col items-center space-y-1 text-yellow-400">
              <div class="w-12 h-12 rounded-full bg-yellow-400 flex items-center justify-center shadow-md">
                <i class="fas fa-book text-white text-xl"></i>
              </div>
            </a>
            <a href="/settings" class="flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-user text-gray-600 text-xl"></i>
              </div>
            </a>
          </div>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          const currentUser = ${JSON.stringify(user)};
          const today = new Date();
          let currentYear = today.getFullYear();
          let currentMonth = today.getMonth() + 1;

          // 초기 년도/월 설정
          document.getElementById('year-select').value = currentYear;
          document.getElementById('month-select').value = currentMonth;

          // 메시지 로드
          async function loadMessages() {
            const year = document.getElementById('year-select').value;
            const month = document.getElementById('month-select').value;
            
            try {
              const response = await fetch('/api/messages/' + year + '/' + month);
              const data = await response.json();
              
              if (data.success && data.messages) {
                displayMessages(data.messages);
              }
            } catch (error) {
              console.error('메시지 로드 실패:', error);
            }
          }

          // 메시지 표시
          function displayMessages(messagesData) {
            const messagesList = document.getElementById('messages-list');
            const noMessages = document.getElementById('no-messages');
            
            // 날짜별로 정렬 (최신순)
            const dates = Object.keys(messagesData).sort().reverse();
            
            if (dates.length === 0) {
              messagesList.innerHTML = '';
              noMessages.classList.remove('hidden');
              return;
            }
            
            noMessages.classList.add('hidden');
            messagesList.innerHTML = '';
            
            const todayKey = new Date().getFullYear() + '-' + String(new Date().getMonth() + 1).padStart(2, '0') + '-' + String(new Date().getDate()).padStart(2, '0');
            
            dates.forEach(date => {
              const dayMessages = messagesData[date];
              const dateObj = new Date(date + 'T00:00:00');
              const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
              const weekdayKr = ['일', '월', '화', '수', '목', '금', '토'];
              const weekday = weekdayKr[dateObj.getDay()];
              const [year, month, day] = date.split('-');
              
              const messageCard = document.createElement('div');
              messageCard.className = 'bg-white rounded-3xl shadow-lg p-6';
              
              let cardHTML = \`
                <div class="flex items-center mb-4 pb-3 border-b-2 border-gray-100">
                  <span class="text-lg font-bold text-gray-800">\${year}년 \${parseInt(month)}월 \${parseInt(day)}일 \${weekday}</span>
                </div>
              \`;
              
              // 남자 메시지
              if (dayMessages.male) {
                cardHTML += \`
                  <div class="mb-4">
                    <div class="flex items-center mb-2">
                      <img src="/static/bear-male.png" alt="남자 곰돌이" class="w-10 h-10 mr-2 object-contain">
                      <span class="text-sm font-semibold text-gray-700">\${dayMessages.male.name || '남자친구'}</span>
                    </div>
                    <div class="bg-amber-50 rounded-2xl p-4 ml-12">
                      <p class="text-gray-800 whitespace-pre-wrap">\${dayMessages.male.content}</p>
                    </div>
                  </div>
                \`;
              }
              
              // 여자 메시지
              if (dayMessages.female) {
                cardHTML += \`
                  <div class="mb-2">
                    <div class="flex items-center mb-2">
                      <img src="/static/bear-female.png" alt="여자 곰돌이" class="w-10 h-10 mr-2 object-contain">
                      <span class="text-sm font-semibold text-gray-700">\${dayMessages.female.name || '여자친구'}</span>
                    </div>
                    <div class="bg-pink-50 rounded-2xl p-4 ml-12">
                      <p class="text-gray-800 whitespace-pre-wrap">\${dayMessages.female.content}</p>
                    </div>
                  </div>
                \`;
              }
              
              // 하단 아이콘
              const hasBoth = dayMessages.male && dayMessages.female;
              const isPast = date < todayKey;
              const showCrying = isPast && !hasBoth;
              const statusImg = hasBoth
                ? '/static/bear-couple.png'
                : (dayMessages.male
                  ? (showCrying ? '/static/bear-male-cry.png' : '/static/bear-male.png')
                  : (showCrying ? '/static/bear-female-cry.png' : '/static/bear-female.png'));
              cardHTML += \`
                <div class="flex justify-end mt-4 pt-3 border-t-2 border-gray-100">
                  <span class="text-sm text-gray-500 flex items-center">
                    <img src="\${statusImg}" alt="상태" class="w-6 h-6 mr-1 object-contain">
                    \${hasBoth ? '두 명 모두 전달 완료' : '한 명만 전달'}
                  </span>
                </div>
              \`;
              
              messageCard.innerHTML = cardHTML;
              messagesList.appendChild(messageCard);
            });
          }

          // 년도/월 변경 이벤트
          document.getElementById('year-select').addEventListener('change', loadMessages);
          document.getElementById('month-select').addEventListener('change', loadMessages);

          // 초기 로드
          loadMessages();
        `
      }} />
    </div>,
    { title: '메시지 히스토리 - 곰아워' }
  )
})

// 설정 페이지
app.get('/settings', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }

  // 성별이나 알림시간이 설정되지 않았으면 설정 페이지로 리다이렉트
  if (!user.gender || !user.notification_time) {
    return c.redirect('/setup')
  }

  // 커플 연동이 안 되어 있어도 접근 가능
  // if (!user.couple_id) {
  //   return c.redirect('/setup')
  // }

  // 사용자 정보 조회
  const dbUser = await c.env.DB.prepare(
    'SELECT * FROM users WHERE id = ?'
  ).bind(user.db_id).first()

  const userName = dbUser?.name || user.name
  const userPicture = user.picture || ''
  const dbCoupleCode = await getCoupleCode(c.env.DB, dbUser?.couple_id as number | null)
  const coupleCode = dbCoupleCode || user.couple_code || ''
  const userGender = (dbUser?.gender as string | null) || user.gender || ''
  const notificationTime = dbUser?.notification_time || user.notification_time || '20:00'
  let metDate = ''
  try {
    metDate = (await getMetDate(c.env.DB, user.db_id, dbUser?.couple_id as number | null)) || ''
  } catch { /* met_date 컬럼 없을 수 있음 */ }

  const coupleId = dbUser?.couple_id as number | null
  let isPartnerLinked = false
  if (coupleId) {
    const coupleCount = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM users WHERE couple_id = ?'
    ).bind(coupleId).first()
    isPartnerLinked = (coupleCount?.count as number) >= 2
  }

  return c.render(
    <div class="min-h-screen pb-32" style="background: linear-gradient(to bottom, #FFF8E7, #FFE4B5);">
      <div class="max-w-md mx-auto px-4 py-6">
        {/* 헤더 */}
        <div class="flex items-center justify-between mb-6">
          <h1 class="text-2xl font-bold text-gray-800">마이페이지</h1>
          <button onclick="window.location.href='/logout'" class="p-2 hover:bg-white rounded-full transition">
            <i class="fas fa-sign-out-alt text-gray-600"></i>
          </button>
        </div>

        {/* 프로필 - 닉네임만 표시 */}
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6 text-center">
          <p class="text-xl font-bold text-gray-800" id="user-name-display">{userName}</p>
          <button id="edit-name-btn" class="text-sm text-gray-500 hover:text-amber-600 transition mt-2">
            <i class="fas fa-pencil-alt mr-1"></i>닉네임 수정
          </button>
        </div>

        {/* 닉네임 수정 모달 */}
        <div id="edit-name-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xl font-bold text-gray-800">닉네임 수정</h3>
              <button id="close-name-modal" class="p-2 hover:bg-gray-100 rounded-full transition">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <input 
              type="text" 
              id="new-name-input"
              value={userName}
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400 focus:border-transparent mb-4"
              placeholder="새 닉네임"
            />
            <button id="save-name-btn" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-check mr-2"></i>저장
            </button>
          </div>
        </div>

        {/* 연동 여부 */}
        <div class="bg-white rounded-3xl shadow-lg p-5 mb-6 text-center">
          <p class="text-base font-semibold text-gray-800">
            {isPartnerLinked ? (
              <span class="text-black font-bold">✅연동 완료</span>
            ) : (
              <span class="text-gray-500">미연동</span>
            )}
          </p>
        </div>

        {/* 내 커플 코드 - 연동 전에만 표시 */}
        {!isPartnerLinked && (
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6">
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center">
              <span class="text-2xl mr-2">🔑</span>
              <p class="text-base font-bold text-gray-800">내 커플 코드</p>
            </div>
            <button id="copy-main-code-btn" class={`text-sm text-amber-600 hover:text-amber-700 font-semibold ${coupleCode ? '' : 'hidden'}`}>
              <i class="fas fa-copy mr-1"></i>복사
            </button>
          </div>
          <div class="bg-gradient-to-br from-amber-100 to-orange-100 rounded-xl p-4 text-center">
            <p class="text-2xl font-mono font-bold text-amber-700" id="main-couple-code">{coupleCode || '------'}</p>
            <p class="text-xs text-gray-600 mt-2">이 코드를 상대방과 공유하세요</p>
          </div>
          {!coupleCode && (
            <button id="create-main-code-btn" class="w-full mt-4 py-3 rounded-xl font-bold text-white text-base shadow-lg hover:shadow-xl transition-all" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-plus mr-2"></i>생성하기
            </button>
          )}
        </div>
        )}

        {/* 메뉴 리스트 - onclick 인라인으로 모달 열기 */}
        <div class="bg-white rounded-3xl shadow-lg overflow-hidden mb-6" style="position:relative;z-index:10">
          <a href="#" onclick={isPartnerLinked ? 'return false' : "document.getElementById('partner-modal').classList.remove('hidden');return false"} class={`settings-menu-item w-full flex items-center justify-between p-5 transition border-b border-gray-100 no-underline text-inherit ${isPartnerLinked ? 'opacity-50 cursor-default pointer-events-none' : 'hover:bg-gray-50 cursor-pointer'}`}>
            <div class="flex items-center">
              <span class="text-2xl mr-3">🔗</span>
              <span class="text-base font-semibold text-gray-800">상대방 계정 연동하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>

          <a id="met-date-btn" href="#" onclick="window.__openMetDate();return false" class={`settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit ${!isPartnerLinked ? 'opacity-50' : ''}`}>
            <div class="flex items-center">
              <span class="text-2xl mr-3">💕</span>
              <span class="text-base font-semibold text-gray-800">우리가 만난 날 설정하기</span>
            </div>
            <div class="flex items-center gap-2">
              {metDate ? <span class="text-sm text-amber-600">{metDate}</span> : null}
              <i class="fas fa-chevron-right text-gray-400"></i>
            </div>
          </a>

          <a href="#" onclick="document.getElementById('notification-modal').classList.remove('hidden');return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">⏰</span>
              <span class="text-base font-semibold text-gray-800">알림 시간 설정하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>

          <a href="#" onclick="document.getElementById('feedback-modal').classList.remove('hidden');return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">💡</span>
              <span class="text-base font-semibold text-gray-800">제안/문의하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>

          <a href="#" onclick="document.getElementById('password-modal').classList.remove('hidden');if(typeof resetPin==='function')resetPin();return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">🔒</span>
              <span class="text-base font-semibold text-gray-800">비밀번호 설정하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>

          <a href="https://gom-hr.com" class="w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">🏠</span>
              <span class="text-base font-semibold text-gray-800">홈페이지 바로가기</span>
            </div>
            <i class="fas fa-external-link-alt text-gray-400 text-sm"></i>
          </a>

          <a href="#" onclick="document.getElementById('delete-account-modal').classList.remove('hidden');return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-red-50 transition no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">🗑️</span>
              <span class="text-base font-semibold text-red-600">계정 삭제하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>
        </div>

        {/* 계정 삭제 확인 모달 */}
        <div id="delete-account-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="text-center mb-6">
              <span class="text-5xl mb-4 block">⚠️</span>
              <h3 class="text-xl font-bold text-gray-800 mb-2">정말 계정을 삭제하시겠습니까?</h3>
              <p class="text-sm text-gray-600 mb-1">삭제된 계정과 모든 데이터는 복구할 수 없습니다.</p>
            </div>
            <div class="flex gap-3">
              <button type="button" onclick="document.getElementById('delete-account-modal').classList.add('hidden')" class="flex-1 py-3 rounded-xl font-semibold text-gray-700 bg-gray-200 hover:bg-gray-300 transition cursor-pointer">
                취소
              </button>
              <button type="button" id="confirm-delete-btn" onclick="window.__confirmDelete()" class="flex-1 py-3 rounded-xl font-bold text-white bg-red-500 hover:bg-red-600 transition cursor-pointer">
                삭제하기
              </button>
            </div>
          </div>
        </div>

        {/* 알림 시간 설정 모달 */}
        <div id="notification-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xl font-bold text-gray-800">알림 시간 설정</h3>
              <button type="button" onclick="document.getElementById('notification-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div class="relative mb-4 date-time-input-wrap">
              <div class="form-input-box w-full px-4 py-3 border-2 border-gray-300 rounded-2xl bg-white text-gray-800" id="notification-time-display">{notificationTime ? (() => { const [h,m]=(notificationTime||'').split(':'); const hh=+h; return hh>=12 ? `오후 ${hh===12?12:hh-12}:${m||'00'}` : `오전 ${hh||12}:${m||'00'}`; })() : '오후 8:00'}</div>
              <input type="time" id="new-notification-time" value={notificationTime} class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            </div>
            <button type="button" onclick="window.__saveNotification()" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-check mr-2"></i>저장
            </button>
          </div>
        </div>

        {/* 커플 미연동 안내 모달 */}
        <div id="partner-required-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[55] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 text-center">
            <p class="text-lg text-gray-800 mb-6">커플 연동 후 설정할 수 있어요</p>
            <button type="button" onclick="document.getElementById('partner-required-modal').classList.add('hidden')" class="w-full py-3 rounded-xl font-bold text-white text-base cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인
            </button>
          </div>
        </div>

        {/* 우리가 만난 날 설정 모달 */}
        <div id="met-date-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-bold text-gray-800">우리가 만난 날 설정하기</h3>
              <button type="button" onclick="document.getElementById('met-date-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div class="relative mb-4 date-time-input-wrap">
              <div class="form-input-box w-full px-4 py-3 border-2 border-gray-300 rounded-2xl bg-white text-gray-800" id="met-date-display">{metDate ? `${metDate.split('-')[0]}. ${parseInt(metDate.split('-')[1],10)}. ${parseInt(metDate.split('-')[2],10)}.` : '날짜 선택'}</div>
              <input type="date" id="new-met-date" value={metDate} class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            </div>
            <button type="button" onclick="window.__saveMetDate()" class="w-full py-3.5 rounded-xl font-bold text-white text-base shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-check mr-2"></i>저장
            </button>
          </div>
        </div>

        {/* 상대방 연동 모달 */}
        <div id="partner-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xl font-bold text-gray-800">상대방 계정 연동</h3>
              <button type="button" onclick="document.getElementById('partner-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <p class="text-sm text-gray-600 mb-4">상대방의 커플 코드를 입력하세요:</p>
            <input 
              type="text" 
              id="partner-code-input"
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-2xl focus:ring-2 focus:ring-amber-400 focus:border-transparent mb-4 text-center text-lg font-mono"
              placeholder="6자리 코드 입력"
              maxlength="6"
            />
            <button type="button" onclick="window.__joinPartner()" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-link mr-2"></i>연동하기
            </button>
          </div>
        </div>

        {/* 비밀번호 설정 모달 */}
        <div id="password-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-2">
              <h3 class="text-xl font-bold text-gray-800">앱 잠금 비밀번호</h3>
              <button type="button" onclick="document.getElementById('password-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <p id="pin-step-text" class="text-sm text-gray-600 mb-4">4자리 비밀번호를 입력하세요</p>
            <div id="pin-dots" class="flex items-center justify-center gap-3 mb-4">
              <span class="w-3 h-3 rounded-full bg-gray-200"></span>
              <span class="w-3 h-3 rounded-full bg-gray-200"></span>
              <span class="w-3 h-3 rounded-full bg-gray-200"></span>
              <span class="w-3 h-3 rounded-full bg-gray-200"></span>
            </div>
            <div class="grid grid-cols-3 gap-3 text-lg font-semibold">
              <button type="button" onclick="window.__pinKey('1')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">1</button>
              <button type="button" onclick="window.__pinKey('2')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">2</button>
              <button type="button" onclick="window.__pinKey('3')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">3</button>
              <button type="button" onclick="window.__pinKey('4')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">4</button>
              <button type="button" onclick="window.__pinKey('5')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">5</button>
              <button type="button" onclick="window.__pinKey('6')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">6</button>
              <button type="button" onclick="window.__pinKey('7')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">7</button>
              <button type="button" onclick="window.__pinKey('8')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">8</button>
              <button type="button" onclick="window.__pinKey('9')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">9</button>
              <div></div>
              <button type="button" onclick="window.__pinKey('0')" class="pin-key py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">0</button>
              <button type="button" onclick="window.__pinDel()" class="py-3 rounded-xl bg-gray-100 hover:bg-gray-200 cursor-pointer">⌫</button>
            </div>
            <p id="pin-error" class="text-center text-sm text-red-500 mt-3 hidden">비밀번호가 일치하지 않습니다.</p>
          </div>
        </div>

        {/* 제안/문의 모달 */}
        <div id="feedback-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xl font-bold text-gray-800">제안/문의하기</h3>
              <button type="button" onclick="document.getElementById('feedback-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <p class="text-sm text-gray-600 mb-4">곰아워를 더 좋게 만들기 위한 제안이나 문의사항을 남겨주세요 💕</p>
            <input 
              type="text" 
              id="feedback-subject"
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400 focus:border-transparent mb-3"
              placeholder="제목"
            />
            <textarea 
              id="feedback-message"
              rows="5"
              class="w-full px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-amber-400 focus:border-transparent mb-4 resize-none"
              placeholder="내용을 입력해주세요"
            ></textarea>
            <button type="button" id="send-feedback-btn" onclick="window.__sendFeedback()" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-paper-plane mr-2"></i>전송하기
            </button>
          </div>
        </div>
      </div>

      {/* 하단 네비게이션 - pointer-events-none으로 배경은 터치 통과, 링크만 pointer-events-auto로 클릭 가능 */}
      <div class="fixed bottom-0 left-0 right-0 py-4 z-40 pointer-events-none" style="background: linear-gradient(to top, rgba(255,248,231,0.98), rgba(255,228,181,0.95)); padding-bottom: max(1rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-8 pointer-events-none">
          <div class="flex items-center justify-between">
            <a href="/dashboard" class="pointer-events-auto flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-calendar text-gray-600 text-xl"></i>
              </div>
            </a>
            <a href="/history" class="pointer-events-auto flex flex-col items-center space-y-1 text-gray-600 hover:text-gray-800 transition">
              <div class="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md">
                <i class="fas fa-book text-gray-600 text-xl"></i>
              </div>
            </a>
            <a href="/settings" class="pointer-events-auto flex flex-col items-center space-y-1 text-yellow-400">
              <div class="w-12 h-12 rounded-full bg-yellow-400 flex items-center justify-center shadow-md">
                <i class="fas fa-user text-white text-xl"></i>
              </div>
            </a>
          </div>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          const currentUser = { name: ${JSON.stringify(userName)}, email: ${JSON.stringify(user.email || user.id || '') }};
          const currentGender = ${JSON.stringify(userGender)};
          const currentNotificationTime = ${JSON.stringify(notificationTime)};
          const currentCoupleCode = ${JSON.stringify(coupleCode)};
          const isPartnerLinked = ${JSON.stringify(isPartnerLinked)};
          
          window.__openMetDate = function() {
            fetch('/api/user/partner-status', { credentials: 'include' }).then(function(r) { return r.json(); }).then(function(data) {
              if (!data.linked) document.getElementById('partner-required-modal').classList.remove('hidden');
              else document.getElementById('met-date-modal').classList.remove('hidden');
            }).catch(function() { document.getElementById('partner-required-modal').classList.remove('hidden'); });
          };
          
          window.__saveNotification = async function() {
            var newTime = document.getElementById('new-notification-time').value;
            try {
              var res = await fetch('/api/user/update-notification', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ notification_time: newTime }) });
              var data = await res.json();
              if (data.success) {
                document.getElementById('notification-modal').classList.add('hidden');
                alert('알림 시간이 변경되었습니다! ⏰');
                try { var pr = await fetch('/api/push/test', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}' }); var pd = await pr.json(); if (pd.success) alert('테스트 푸시를 보냈어요! 📱'); else if (pd.error && pd.error.includes('등록된 디바이스')) alert('알림 시간 저장됐어요! ⏰\\n(푸시는 앱을 다시 켜고 설정 화면에 들어온 뒤에 등록돼요)'); } catch(e) {}
              } else alert(data.error || '알림 시간 변경에 실패했습니다.');
            } catch (e) { alert('알림 시간 변경 중 오류가 발생했습니다.'); }
          };
          
          window.__saveMetDate = async function() {
            var newDate = document.getElementById('new-met-date').value;
            if (!newDate) { alert('날짜를 선택해주세요.'); return; }
            try {
              var res = await fetch('/api/user/update-met-date', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ met_date: newDate }) });
              var data = await res.json();
              if (data.success) {
                document.getElementById('met-date-modal').classList.add('hidden');
                var btn = document.getElementById('met-date-btn');
                var span = btn.querySelector('.flex.items-center.gap-2 span');
                if (span) span.textContent = newDate; else { var div = btn.querySelector('.flex.items-center.gap-2'); var s = document.createElement('span'); s.className = 'text-sm text-amber-600'; s.textContent = newDate; div.insertBefore(s, div.firstChild); }
                alert('우리가 만난 날이 저장되었습니다! 💕');
              } else alert(data.error || '저장에 실패했습니다.');
            } catch (e) { alert('저장 중 오류가 발생했습니다.'); }
          };
          
          window.__sendFeedback = async function() {
            var subject = document.getElementById('feedback-subject').value.trim();
            var message = document.getElementById('feedback-message').value.trim();
            if (!subject || !message) { alert('제목과 내용을 모두 입력해주세요!'); return; }
            var btn = document.getElementById('send-feedback-btn');
            if (btn.getAttribute('data-sending') === '1') return;
            btn.setAttribute('data-sending', '1');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>전송 중...';
            try {
              var res = await fetch('/api/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ subject, message }) });
              var data = await res.json();
              if (data.success) {
                document.getElementById('feedback-modal').classList.add('hidden');
                document.getElementById('feedback-subject').value = '';
                document.getElementById('feedback-message').value = '';
                alert('문의가 전송되었습니다. 빠른 시일 내에 답변 드리겠습니다. 💕');
              } else alert(data.error || '전송에 실패했습니다.');
            } catch (e) { alert('전송 중 오류가 발생했습니다.'); }
            finally { btn.removeAttribute('data-sending'); btn.innerHTML = '<i class="fas fa-paper-plane mr-2"></i>전송하기'; }
          };
          
          window.__confirmDelete = async function() {
            var btn = document.getElementById('confirm-delete-btn');
            if (btn && btn.getAttribute('data-deleting') === '1') return;
            if (btn) { btn.setAttribute('data-deleting', '1'); btn.textContent = '삭제 중...'; }
            try {
              var res = await fetch('/api/user/delete-account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: '{}' });
              var data = await res.json();
              if (data.success) window.location.href = '/app/login';
              else alert(data.error || '계정 삭제에 실패했습니다.');
            } catch (e) { alert('계정 삭제 중 오류가 발생했습니다.'); }
            finally { if (btn) { btn.removeAttribute('data-deleting'); btn.textContent = '삭제하기'; } }
          };
          
          window.__joinPartner = async function() {
            var partnerCode = document.getElementById('partner-code-input').value.trim().toUpperCase();
            if (!partnerCode || partnerCode.length !== 6) { alert('6자리 커플 코드를 입력해주세요!'); return; }
            try {
              var res = await fetch('/api/couple/join', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ couple_code: partnerCode }) });
              var data = await res.json();
              if (data.success) { alert('상대방과 연동되었습니다! 💕'); window.location.href = '/dashboard'; }
              else alert(data.error || '연동에 실패했습니다.');
            } catch (e) { alert('연동 중 오류가 발생했습니다.'); }
          };
          
          // 닉네임 수정
          document.getElementById('edit-name-btn').addEventListener('click', () => {
            document.getElementById('edit-name-modal').classList.remove('hidden');
          });

          document.getElementById('close-name-modal').addEventListener('click', () => {
            document.getElementById('edit-name-modal').classList.add('hidden');
          });

          document.getElementById('save-name-btn').addEventListener('click', async () => {
            const newName = document.getElementById('new-name-input').value.trim();
            if (!newName) {
              alert('닉네임을 입력해주세요!');
              return;
            }

            try {
              const response = await fetch('/api/user/update-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ name: newName })
              });

              const data = await response.json();
              if (data.success) {
                document.getElementById('user-name-display').textContent = newName;
                document.getElementById('edit-name-modal').classList.add('hidden');
                alert('닉네임이 변경되었습니다! 💕');
              } else {
                alert(data.error || '닉네임 변경에 실패했습니다.');
              }
            } catch (error) {
              console.error('닉네임 변경 오류:', error);
              alert('닉네임 변경 중 오류가 발생했습니다.');
            }
          });

          // 알림 시간 설정
          const timeDisplay = document.getElementById('notification-time-display');
          const timeInput = document.getElementById('new-notification-time');
          const fmtTime = (v) => { if (!v) return '20:00'; const [h,m]=v.split(':'); const hh=+h; return hh>=12 ? '오후 '+(hh===12?12:hh-12)+':'+(m||'00') : '오전 '+(hh||12)+':'+(m||'00'); };
          if (timeDisplay && timeInput) {
            timeInput.addEventListener('input', () => { timeDisplay.textContent = fmtTime(timeInput.value); });
            timeInput.addEventListener('change', () => { timeDisplay.textContent = fmtTime(timeInput.value); });
          }

          const dateDisplay = document.getElementById('met-date-display');
          const dateInput = document.getElementById('new-met-date');
          const fmtDate = (v) => { if (!v) return '날짜 선택'; const [y,m,d]=v.split('-'); return y+'. '+parseInt(m,10)+'. '+parseInt(d,10)+'.'; };
          if (dateDisplay && dateInput) {
            dateInput.addEventListener('input', () => { dateDisplay.textContent = fmtDate(dateInput.value); });
            dateInput.addEventListener('change', () => { dateDisplay.textContent = fmtDate(dateInput.value); });
          }

          // 커플 코드 생성 (마이페이지)
          const createMainCodeBtn = document.getElementById('create-main-code-btn');
          if (createMainCodeBtn) {
            createMainCodeBtn.addEventListener('click', async () => {
              if (!currentGender) {
                alert('성별 설정이 필요합니다. 설정 페이지로 이동합니다.');
                window.location.href = '/setup';
                return;
              }

              try {
                const response = await fetch('/api/couple/create', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    gender: currentGender,
                    notification_time: currentNotificationTime || '20:00'
                  })
                });

                const data = await response.json();
                if (data.success) {
                  document.getElementById('main-couple-code').textContent = data.couple_code;
                  createMainCodeBtn.remove();
                  alert('커플 코드가 생성되었습니다! 💕');
                } else {
                  alert(data.error || '커플 코드 생성에 실패했습니다.');
                }
              } catch (error) {
                console.error('커플 코드 생성 오류:', error);
                alert('커플 코드 생성 중 오류가 발생했습니다.');
              }
            });
          }

          // 상대방 코드로 연동
          // 메인 코드 복사
          document.getElementById('copy-main-code-btn').addEventListener('click', () => {
            const code = '${coupleCode}';
            navigator.clipboard.writeText(code);
            alert('커플 코드가 복사되었어요! 💕');
          });

          const pinDots = document.querySelectorAll('#pin-dots span');
          const pinStepText = document.getElementById('pin-step-text');
          let pinStep = 1;
          let firstPin = '';
          let pinValue = '';

          function renderPinDots() {
            pinDots.forEach((dot, idx) => {
              dot.classList.toggle('bg-amber-400', idx < pinValue.length);
              dot.classList.toggle('bg-gray-200', idx >= pinValue.length);
            });
          }

          function resetPin() {
            pinStep = 1;
            firstPin = '';
            pinValue = '';
            pinStepText.textContent = '4자리 비밀번호를 입력하세요';
            document.getElementById('pin-error').classList.add('hidden');
            renderPinDots();
          }

          window.__pinKey = function(digit) {
            if (pinValue.length >= 4) return;
            pinValue += digit;
            renderPinDots();
            if (pinValue.length === 4) {
              if (pinStep === 1) {
                firstPin = pinValue;
                pinValue = '';
                pinStep = 2;
                pinStepText.textContent = '비밀번호를 한 번 더 입력하세요';
                renderPinDots();
              } else {
                if (pinValue !== firstPin) {
                  document.getElementById('pin-error').classList.remove('hidden');
                  pinValue = '';
                  renderPinDots();
                  return;
                }
                fetch('/api/user/update-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ password: pinValue }) })
                  .then(function(r) { return r.json(); })
                  .then(function(data) {
                    if (data.success) { document.getElementById('password-modal').classList.add('hidden'); alert('비밀번호가 설정되었습니다! 🔒'); }
                    else alert(data.error || '비밀번호 설정에 실패했습니다.');
                  })
                  .catch(function() { alert('비밀번호 설정 중 오류가 발생했습니다.'); })
                  .finally(function() { resetPin(); });
              }
            }
          };

          window.__pinDel = function() {
            if (pinValue.length > 0) { pinValue = pinValue.slice(0, -1); renderPinDots(); }
          };


        `
      }} />
    </div>,
    { title: '설정 - 곰아워' }
  )
})

// 헬스 체크 API
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
      maxAge: 60 * 60 * 24 * 365,
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
      maxAge: 60 * 60 * 24 * 365,
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

    // 커플 연동 상태면 상대방에게 푸시 전송 (DB 기준 couple_id 사용)
    const dbUser = await c.env.DB.prepare('SELECT couple_id, name FROM users WHERE id = ?')
      .bind(user.db_id).first()
    const coupleId = dbUser?.couple_id as number | null
    if (coupleId) {
      const partner = await c.env.DB.prepare(
        'SELECT id FROM users WHERE couple_id = ? AND id != ? LIMIT 1'
      ).bind(coupleId, user.db_id).first()

      if (partner?.id) {
        const tokens = await c.env.DB.prepare(
          'SELECT token FROM device_tokens WHERE user_id = ?'
        ).bind(partner.id).all()

        const senderName = (dbUser?.name as string) || user.name || '상대방'
        const pushMessage = `${senderName}님이 곰아워했어요🧡`
        for (const tokenRow of tokens.results as any[]) {
          try {
            const response = await sendApns(c.env, tokenRow.token, pushMessage)
            if (!response.ok) {
              const errorText = await response.text()
              console.error('APNs 전송 실패:', response.status, errorText)
            }
          } catch (e) {
            console.error('APNs 전송 오류:', e)
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

// 커플 연동 여부 확인 (만난 날 설정 등에서 사용)
app.get('/api/user/partner-status', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ linked: false }, 401)
  }
  const user: User = JSON.parse(userSessionCookie)
  const dbUser = await c.env.DB.prepare('SELECT couple_id FROM users WHERE id = ?')
    .bind(user.db_id).first()
  const coupleId = dbUser?.couple_id as number | null
  if (!coupleId) {
    return c.json({ linked: false })
  }
  const coupleCount = await c.env.DB.prepare(
    'SELECT COUNT(*) as count FROM users WHERE couple_id = ?'
  ).bind(coupleId).first()
  const linked = (coupleCount?.count as number) >= 2
  return c.json({ linked })
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
      maxAge: 60 * 60 * 24 * 365,
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
  const body = await c.req.json()
  let notification_time = (body.notification_time || '').trim()

  if (!notification_time) {
    return c.json({ success: false, error: '알림 시간을 입력해주세요.' }, 400)
  }

  // HH:mm 형식으로 정규화 (9:00 -> 09:00)
  const parts = notification_time.split(':')
  if (parts.length >= 2) {
    const h = parseInt(parts[0], 10)
    const m = parseInt(parts[1], 10) || 0
    if (!isNaN(h) && !isNaN(m)) {
      notification_time = String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0')
    }
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

// 우리가 만난 날 업데이트 (연동 없이도 users에 저장 가능 - 테스트용)
app.post('/api/user/update-met-date', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { met_date } = await c.req.json()

  if (!met_date || !/^\d{4}-\d{2}-\d{2}$/.test(met_date)) {
    return c.json({ success: false, error: '올바른 날짜를 입력해주세요.' }, 400)
  }

  const dbUser = await c.env.DB.prepare(
    'SELECT couple_id FROM users WHERE id = ?'
  ).bind(user.db_id).first()

  const coupleId = dbUser?.couple_id as number | null

  try {
    if (coupleId) {
      await c.env.DB.prepare(
        'UPDATE couples SET met_date = ? WHERE id = ?'
      ).bind(met_date, coupleId).run()
    } else {
      await c.env.DB.prepare(
        'UPDATE users SET met_date = ? WHERE id = ?'
      ).bind(met_date, user.db_id).run()
    }
    return c.json({ success: true })
  } catch (error) {
    console.error('만난 날 업데이트 오류:', error)
    return c.json({ success: false, error: '저장 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 설정 건너뛰기 - 폼 제출용 (WebView에서 리다이렉트 안정적)
app.post('/setup/skip', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.redirect('/app/login')
  }

  const user: User = JSON.parse(userSessionCookie)
  let body: { gender?: string; notification_time?: string; name?: string }
  const contentType = c.req.header('Content-Type') || ''
  if (contentType.includes('application/json')) {
    body = await c.req.json()
  } else {
    const form = await c.req.parseBody()
    body = {
      gender: form.gender as string,
      notification_time: (form.notification_time as string) || '20:00',
      name: (form.name as string) || user.name
    }
  }

  if (!body.gender) {
    return c.redirect('/setup?error=gender')
  }

  try {
    await c.env.DB.prepare(
      'UPDATE users SET gender = ?, notification_time = ?, name = ? WHERE id = ?'
    ).bind(body.gender, body.notification_time || '20:00', (body.name || user.name)?.trim() || user.name, user.db_id).run()

    user.gender = body.gender
    user.notification_time = body.notification_time || '20:00'
    if (body.name?.trim()) user.name = body.name.trim()
    user.setup_done = true
    setCookie(c, 'user_session', JSON.stringify(user), {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 365,
      sameSite: 'Lax'
    })
    if (user.email === 'admin@gomawo.app') {
      deleteCookie(c, 'admin_force_setup', { path: '/', domain: 'gom-hr.com' })
    }
    return c.redirect('/dashboard?show_promise=1&from_setup=1')
  } catch (error) {
    console.error('설정 저장 오류:', error)
    return c.redirect('/setup?error=save')
  }
})

// 커플 설정 건너뛰기 (나중에 하기) - API
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
      maxAge: 60 * 60 * 24 * 365,
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
  const body = await c.req.json()
  const password = body.password != null ? String(body.password) : ''

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
  const body = await c.req.json()
  const pin = body.pin != null ? String(body.pin) : ''

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

// 푸시 테스트 (수동 발송 - 디버깅용)
app.post('/api/push/test', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  try {
    const tokens = await c.env.DB.prepare(
      'SELECT token FROM device_tokens WHERE user_id = ?'
    ).bind(user.db_id).all()

    const tokenRows = (tokens.results || []) as { token: string }[]
    if (tokenRows.length === 0) {
      return c.json({ success: false, error: '등록된 디바이스 토큰이 없습니다. 대시보드/설정 화면에 진입한 뒤 다시 시도해주세요.' })
    }

    const results: { token: string; success: boolean; status?: number; error?: string }[] = []
    for (const row of tokenRows) {
      const response = await sendApns(c.env, row.token, '🧪 푸시 테스트 - 곰아워가 잘 되나요?')
      const errorText = await response.text()
      results.push({
        token: row.token.substring(0, 20) + '...',
        success: response.ok,
        status: response.status,
        error: response.ok ? undefined : errorText
      })
    }

    const allOk = results.every(r => r.success)
    return c.json({
      success: allOk,
      message: allOk ? '푸시 전송 성공!' : '일부 또는 전체 실패. error 필드 확인.',
      results,
      hint: 'APNs 400/403: 토큰/키 문제. Sandbox 빌드면 APNS_USE_SANDBOX=true 필요.'
    })
  } catch (error) {
    console.error('푸시 테스트 오류:', error)
    return c.json({ success: false, error: String(error) }, 500)
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
    `이메일: ${user.email || user.id || '(알 수 없음)'}`,
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
      maxAge: 60 * 60 * 24 * 365,
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

    // 나의 메시지 삭제
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
  return c.redirect('/app/login')
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

// KST 시간 HH:mm (Intl 의존 없이 직접 계산 - Workers 환경 호환)
const getKstTime = () => {
  const now = new Date()
  const utcMs = now.getTime()
  const kstMs = utcMs + 9 * 60 * 60 * 1000
  const kst = new Date(kstMs)
  const h = kst.getUTCHours()
  const m = kst.getUTCMinutes()
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0')
}

// KST 날짜 YYYY-MM-DD (Workers 환경 호환)
const getKstDate = () => {
  const now = new Date()
  const utcMs = now.getTime()
  const kstMs = utcMs + 9 * 60 * 60 * 1000
  const kst = new Date(kstMs)
  const y = kst.getUTCFullYear()
  const m = kst.getUTCMonth() + 1
  const d = kst.getUTCDate()
  return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`
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

    // 1) 커플 연동된 사용자: 상대방 이름 포함 메시지
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

    // 2) 커플 미연동 사용자(나중에 하기): 일반 리마인더
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
