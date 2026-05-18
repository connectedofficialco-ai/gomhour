import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, deleteCookie, setCookie } from 'hono/cookie'
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from 'jose'
import { renderer } from './renderer'
import kakaoAuth from './routes/kakao'
import type { Bindings, User } from './types'
import { withPublicCookieDomain } from './cookie-public'
import { LOVE_QUOTES_WITH_SOURCE } from './love-quotes'

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

const getTodayKst = () => {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Seoul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date())
}

const ensureJackpotTables = async (db: Bindings['DB']) => {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS jackpot_draws (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      couple_id INTEGER NOT NULL,
      drawer_user_id INTEGER NOT NULL,
      draw_date TEXT NOT NULL,
      quote TEXT NOT NULL,
      quote_source TEXT NOT NULL DEFAULT '출처 미상',
      cost INTEGER NOT NULL DEFAULT 5,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ).run()
  await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_jackpot_draws_couple_date ON jackpot_draws (couple_id, draw_date)').run()
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_jackpot_draws_couple_id ON jackpot_draws (couple_id)').run()

  await db.prepare(
    `CREATE TABLE IF NOT EXISTS jackpot_saved_quotes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      couple_id INTEGER NOT NULL,
      draw_id INTEGER NOT NULL,
      saved_by_user_id INTEGER NOT NULL,
      quote TEXT NOT NULL,
      quote_source TEXT NOT NULL DEFAULT '출처 미상',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ).run()
  await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_jackpot_saved_quotes_couple_quote ON jackpot_saved_quotes (couple_id, quote)').run()

  try {
    await db.prepare("ALTER TABLE jackpot_draws ADD COLUMN quote_source TEXT NOT NULL DEFAULT '출처 미상'").run()
  } catch {}
  try {
    await db.prepare("ALTER TABLE jackpot_saved_quotes ADD COLUMN quote_source TEXT NOT NULL DEFAULT '출처 미상'").run()
  } catch {}
}

const ensureLoveLanguageTables = async (db: Bindings['DB']) => {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS love_language_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      couple_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      top1 TEXT NOT NULL,
      top2 TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ).run()
  await db.prepare(
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_love_language_results_couple_user ON love_language_results (couple_id, user_id)'
  ).run()
  await db.prepare(
    'CREATE INDEX IF NOT EXISTS idx_love_language_results_couple ON love_language_results (couple_id)'
  ).run()
}

const ensureCareMissionTables = async (db: Bindings['DB']) => {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS care_mission_assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      couple_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      partner_user_id INTEGER NOT NULL,
      mission_key TEXT NOT NULL,
      mission_category TEXT NOT NULL,
      mission_title TEXT NOT NULL,
      mission_body TEXT NOT NULL,
      opened_at TEXT,
      skipped_at TEXT,
      completed_at TEXT,
      seen_by_partner INTEGER NOT NULL DEFAULT 0,
      seen_at TEXT
    )`
  ).run()
  await db.prepare(
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_care_mission_unique ON care_mission_assignments (couple_id, user_id, mission_key)'
  ).run()
  await db.prepare(
    'CREATE INDEX IF NOT EXISTS idx_care_mission_partner_unseen ON care_mission_assignments (partner_user_id, seen_by_partner, completed_at)'
  ).run()
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS care_mission_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      couple_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      mission_key TEXT NOT NULL,
      event_type TEXT NOT NULL,
      amount INTEGER NOT NULL,
      label TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`
  ).run()
  await db.prepare(
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_care_mission_event_unique ON care_mission_events (couple_id, user_id, mission_key, event_type)'
  ).run()
}

const getMissionPeriodKey = () => {
  const kstNow = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Seoul' }))
  const day = kstNow.getDay() // 0(sun)~6(sat)
  const slot = day >= 1 && day <= 4 ? 'A' : 'B' // 주 2회
  const diffToMonday = day === 0 ? -6 : 1 - day
  const monday = new Date(kstNow)
  monday.setDate(kstNow.getDate() + diffToMonday)
  const weekStart = formatLocalDate(monday)
  return `${weekStart}-${slot}`
}

const getTodayMissionWindow = (coupleId: number) => {
  const kstNow = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Seoul' }))
  const day = kstNow.getDay() // 0~6
  const diffToMonday = day === 0 ? -6 : 1 - day
  const monday = new Date(kstNow)
  monday.setDate(kstNow.getDate() + diffToMonday)
  const weekStart = formatLocalDate(monday)
  const seedRaw = `${weekStart}:${coupleId}`
  const seed = Array.from(seedRaw).reduce((acc, ch) => acc + ch.charCodeAt(0), 0)
  const first = seed % 7
  let second = (seed * 3 + 5) % 7
  if (second === first) second = (second + 2) % 7
  const missionDays = [first, second].sort((a, b) => a - b)
  const isMissionDay = missionDays.includes(day)
  const slot = day === missionDays[0] ? 'A' : 'B'
  return {
    weekStart,
    isMissionDay,
    missionKey: `${weekStart}-${slot}`,
  }
}

const MISSION_CATEGORY_TO_LOVE: Record<string, string> = {
  words: '인정의 말',
  time: '함께하는 시간',
  gift: '선물',
  service: '봉사',
  touch: '스킨십',
}

const MESSAGE_SIGNAL_PATTERNS: Record<'words' | 'time' | 'gift' | 'service' | 'touch', RegExp[]> = {
  words: [/고마워/g, /칭찬/g, /응원/g, /말해/g, /듣고/g, /격려/g, /수고/g],
  time: [/같이/g, /함께/g, /시간/g, /대화/g, /데이트/g, /산책/g, /통화/g, /안부/g],
  gift: [/선물/g, /준비/g, /챙겨/g, /간식/g, /커피/g, /기프티콘/g, /사진/g, /노래/g],
  service: [/도와/g, /해줘/g, /수고/g, /정리/g, /설거지/g, /집안일/g, /대신/g, /처리/g],
  touch: [/안아/g, /포옹/g, /손잡/g, /스킨십/g, /기대/g, /뽀뽀/g, /키스/g],
}

const scoreSignalsFromAllMessages = (allTextsJoined: string) => {
  const scores: Record<'words' | 'time' | 'gift' | 'service' | 'touch', number> = {
    words: 0,
    time: 0,
    gift: 0,
    service: 0,
    touch: 0,
  }
  ;(Object.keys(MESSAGE_SIGNAL_PATTERNS) as Array<keyof typeof MESSAGE_SIGNAL_PATTERNS>).forEach((key) => {
    const patterns = MESSAGE_SIGNAL_PATTERNS[key]
    let hitCount = 0
    for (const pattern of patterns) {
      const matches = allTextsJoined.match(pattern)
      hitCount += matches ? matches.length : 0
    }
    // 단어 빈도 점수를 완만하게 반영 (과도한 치우침 방지)
    scores[key] += Math.min(8, hitCount)
  })
  return scores
}

const getMissionToneFromRecentMessages = (recentTextsJoined: string) => {
  if (/(힘들|피곤|지쳤|바빴|스트레스|우울|걱정)/.test(recentTextsJoined)) return 'comfort'
  if (/(고마|감사|행복|좋았|기뻤|설렜)/.test(recentTextsJoined)) return 'warm'
  return 'light'
}

const applyMissionTone = (body: string, tone: 'comfort' | 'warm' | 'light') => {
  if (!body) return body
  if (tone === 'comfort') return `오늘은 더 부드럽게, 부담 없이 해봐요. ${body}`
  if (tone === 'warm') return `따뜻한 마음이 잘 전해지도록 해봐요. ${body}`
  return `가볍게 실천해볼까요? ${body}`
}

const CARE_MISSION_OPEN_COST = 5
const CARE_MISSION_COMPLETE_REWARD = 10

const CARE_MISSION_POOL: Record<'words' | 'time' | 'service' | 'gift' | 'touch', string[]> = {
  words: [
    '상대방이 노력하고 있는 일을 알아채고 구체적으로 칭찬해주기', '"보고 싶다" 한 줄 보내기', '자기 전에 "잘 자, 사랑해" 인사 전하기', '하루 중에 "지금 네 생각났어" 메시지 보내기',
    '"사랑해" 음성 메시지 녹음해서 보내기', '"오늘 뭐 했어?" 묻고 끝까지 들어주기', '"오늘도 수고했어" 한 번 말하기', '"ㅇㅇ" "ㅎㅎ" 대신 마음 담은 한 문장으로 답장하기',
    '아침에 "잘 잤어?" 다정하게 인사하기', '하루를 마무리하며 "사랑해" 말하기', '"너 덕분에 ~할 수 있었어" 한 번 말하기', '좋아하는 점 한 가지 적어서 보내기',
    '어제 들은 이야기 기억해서 "그거 어떻게 됐어?" 물어보기', '다정한 톤으로 이름 한 번 부르기', '작은 일에도 "오늘 잘했어" 말해주기', '좋아하는 점 다섯 가지 한꺼번에 적어 보내기',
    '오늘 첫 인사를 다정하게 시작하기', '"오늘 힘든 일 없었어?" 한 번 물어보기', '외출할 때 "잘 다녀와, 응원할게" 인사하기', '자기 전에 "사랑해" 한 번 말하기',
  ],
  time: [
    '5분 동안 그냥 통화하기', '자기 전에 짧게 대화 나누기', '1분이라도 얼굴 보며 안부 묻기', '"오늘 어땠어?" 묻고 5분 동안 들어주기',
    '"지금 뭐 해?" 한 번 물어보기', '지금 보고 있는 풍경 사진 찍어 보내기', '좋아할 만한 노래 한 곡 골라서 공유하기', '식사할 때 휴대폰 엎어두고 먹기',
    '5분 동안 휴대폰 끄고 눈 마주치며 대화하기', '점심시간에 5분 안부 나누기', '"다음에 같이 뭐 하고 싶어?" 한 가지 정해보기', '자기 전에 오늘 가장 좋았던 일 한 가지씩 공유하기',
    '출퇴근 시간에 5분 안부 통화하기', '다음 약속 함께 정하기', '짧은 영상 하나 공유하고 감상 한 줄씩 나누기', '같이 10분 산책하기',
    '둘만 아는 추억이나 농담 한 번 꺼내기', '"오늘 하루 1점부터 10점이면 몇 점이야?" 물어보고 이유 들어주기', '어제 한 대화 이어서 물어보기', '함께 하고 싶은 버킷리스트 한 가지 추가하기',
  ],
  service: [
    '"내일 그거 있다며" 다음 일정 미리 챙겨주기', '"오늘 컨디션 어때?" 한 번 챙겨 묻기', '"점심 먹었어?" 식사 시간 챙겨주기', '"오늘 점심 뭐 먹지?" 메뉴 추천 보내주기',
    '좋아하는 음료나 간식 깜짝 챙겨주기', '좋아할 만한 음식 한 번 챙겨주기', '아침에 다정한 안부 메시지 보내기', '"오늘 일찍 자, 푹 쉬어" 한 번 챙겨주기',
    '일하는 중간에 "잠깐 쉬어" 한 번 챙겨주기', '"물 잘 챙겨 마셔" 건강 한 마디 전하기', '"도와줄 거 있어?" 먼저 물어보기', '"오늘은 내가 처리할게" 한 가지 부담 덜어주기',
    '상대방이 미루는 일 한 가지 가볍게 거들어주기', '도움 될 정보 한 가지 미리 찾아 보내주기', '신경 쓰던 일 한 가지 대신 알아봐주기', '결정하기 귀찮은 일 대신 정해주기',
    '다음에 함께 할 일 한 가지 미리 정해두기', '평소 좋아한다고 한 것 한 번 챙겨주기', '"오늘 뭐가 제일 힘들었어?" 듣고 방법 같이 생각해주기', '자기 전에 내일 응원 한 마디 전하기',
  ],
  gift: [
    '깜짝 커피 기프티콘 보내기', '길 가다 본 거 사진 찍어서 "이거 너 생각났어" 보내기', '함께 찍은 옛날 사진 한 장 보내며 "기억나?" 묻기', '좋아할 만한 노래 한 곡 추천 보내기',
    '좋은 글귀나 시 캡처해서 보내기', '5초짜리 영상 찍어 "여기 같이 오고 싶다" 보내기', '1분 음성 편지 녹음해서 보내기', '마음에 드는 짤 보내며 "이거 너 같아" 말하기',
    '좋아하는 식당 메뉴 사진 보내며 "다음에 같이 먹자" 말하기', '직접 그린 낙서나 하트 사진 찍어 보내기', '좋아할 만한 책/영상 추천 보내기', '좋은 향이나 꽃 사진 보내며 한 줄 메시지',
    '좋아하는 간식 한 번 챙겨주기', '사탕이나 초콜릿 한 개 건네주기', '손글씨 포스트잇 한 줄 건네주기', '함께 찍은 사진 한 장 인쇄해서 주기',
    '좋아하는 음료 한 번 챙겨주기', '평소 사고 싶다 했던 거 기억해뒀다 사주기', '오는 길에 작은 거 하나 사다 주기', '카톡 프로필 사진을 둘이 함께 찍은 사진으로 바꾸기',
  ],
  touch: [
    '20초 이상 꼭 안아주기', '손 한 번 잡기', '어깨 살짝 두드려주기', '머리 한 번 쓰다듬어주기',
    '팔짱 끼고 걷기', '어깨에 잠깐 기대기', '등 가볍게 토닥여주기', '볼에 가벼운 뽀뽀하기',
    '손깍지 끼고 잡기', '헤어지거나 잠들기 전에 한 번 더 안아주기', '머리카락 한 번 정리해주기', '안고 있을 때 천천히 깊게 세 번 숨쉬기',
    '등 한 번 천천히 쓸어주기', '손 잡은 채로 1분 가만히 있기', '카페나 식탁에서 발/무릎 닿게 앉기', '옆에 앉을 때 손등에 손 살짝 올리기',
    '인사할 때 가볍게 한 번 안아주기', '자연스럽게 이마/볼/입술 중 한 곳에 키스하기', '"안아도 돼?" 묻고 안아주기', '잠깐 끌어안고 등 토닥여주기',
  ],
}

const buildMissionFromSignals = (signalScores: Record<string, number>, partnerName: string, missionKey: string) => {
  const ranked = Object.entries(signalScores).sort((a, b) => b[1] - a[1])
  const topCategory = (ranked[0]?.[0] || 'words') as 'words' | 'time' | 'gift' | 'service' | 'touch'
  const otherCategories = (['words', 'time', 'gift', 'service', 'touch'] as const).filter((c) => c !== topCategory)
  const seed = Array.from(missionKey).reduce((acc, ch) => acc + ch.charCodeAt(0), 0)
  const useTopCategory = (seed % 10) < 7 // 70%
  const pickedCategory = useTopCategory
    ? topCategory
    : otherCategories[seed % otherCategories.length]
  const pool = CARE_MISSION_POOL[pickedCategory]
  const missionText = pool[seed % pool.length]
  const title = `${partnerName} 맞춤 ${MISSION_CATEGORY_TO_LOVE[pickedCategory]} 미션`
  return {
    category: pickedCategory,
    love_label: MISSION_CATEGORY_TO_LOVE[pickedCategory],
    title,
    body: missionText,
  }
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
      deleteCookie(c, 'user_session', withPublicCookieDomain(c.req.url, { path: '/' }))
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

// "한 번 로그인하면 사실상 계속 유지"를 위해 10년으로 설정
const SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 10
const FROM_APP_COOKIE_MAX_AGE = 60 * 60 * 24 * 365
const JACKPOT_COST = 5
const LEGACY_QUOTE_SOURCE = '사랑과 연결감 글귀 모음'
const quoteSourceMap = new Map(LOVE_QUOTES_WITH_SOURCE.map((item) => [item.text, item.source]))

const resolveQuoteSource = (quote?: string | null, source?: string | null) => {
  const normalizedSource = String(source || '').trim()
  if (normalizedSource && normalizedSource !== '출처 미상' && normalizedSource !== LEGACY_QUOTE_SOURCE) {
    return normalizedSource
  }
  const normalizedQuote = String(quote || '').trim()
  return quoteSourceMap.get(normalizedQuote) || normalizedSource || '출처 미상'
}

const pickRandomLoveQuote = () => {
  const raw = LOVE_QUOTES[Math.floor(Math.random() * LOVE_QUOTES.length)] || '우리의 사랑은 오늘도 자라고 있어요.'
  const text = String(raw || '').trim() || '우리의 사랑은 오늘도 자라고 있어요.'
  return { text, source: '출처 미상' }
}

const setFromAppCookie = (c: Parameters<typeof setCookie>[0]) => {
  setCookie(
    c,
    'from_app',
    '1',
    withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: false,
      maxAge: FROM_APP_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
  )
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

// API 호출마다 세션·앱 쿠키 슬라이딩 (WebView에서 fetch만 쓰는 화면에서도 로그인 유지)
app.use('/api/*', async (c, next) => {
  if (c.req.method === 'OPTIONS') {
    await next()
    return
  }
  if (getCookie(c, 'from_app') === '1') {
    setFromAppCookie(c)
  }
  const raw = getCookie(c, 'user_session')
  if (raw) {
    try {
      JSON.parse(raw)
      setCookie(
        c,
        'user_session',
        raw,
        withPublicCookieDomain(c.req.url, {
          path: '/',
          httpOnly: true,
          maxAge: SESSION_COOKIE_MAX_AGE,
          sameSite: 'Lax',
        })
      )
    } catch {
      /* invalid cookie */
    }
  }
  await next()
})

// 소셜 로그인 라우트 등록
app.route('/auth/kakao', kakaoAuth)

// 앱 주요 화면 GET마다 세션 쿠키 만료 갱신 (슬라이딩) — 조용히 풀리는 현상 완화
const SESSION_TOUCH_PREFIXES = ['/app', '/dashboard', '/setup', '/history', '/mypage', '/settings', '/account-settings', '/jackpot', '/collage', '/signup'] as const
app.use('*', async (c, next) => {
  if (c.req.method !== 'GET') {
    await next()
    return
  }
  const path = new URL(c.req.url).pathname
  const shouldTouch = SESSION_TOUCH_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`))
  if (shouldTouch) {
    if (getCookie(c, 'from_app') === '1') {
      setFromAppCookie(c)
    }
    const raw = getCookie(c, 'user_session')
    if (raw) {
      try {
        JSON.parse(raw)
        setCookie(
          c,
          'user_session',
          raw,
          withPublicCookieDomain(c.req.url, {
            path: '/',
            httpOnly: true,
            maxAge: SESSION_COOKIE_MAX_AGE,
            sameSite: 'Lax',
          })
        )
      } catch {
        /* 잘못된 세션 JSON은 건드리지 않음 */
      }
    }
  }
  await next()
})

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
const renderLoginPage = (errorMessage?: string, redirect?: string) => (
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
        {redirect && <input type="hidden" name="redirect" value={redirect} />}
          <input
            type="email"
            name="email"
            required
            class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
            placeholder="이메일"
          />
          <input
            type="password"
            name="password"
            required
            class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
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
  setFromAppCookie(c)
  const user = await getValidUserSession(c)
  if (user) {
    if (user.setup_done) return c.redirect('/dashboard')
    return c.redirect('/setup')
  }
  return c.redirect('/app/login')
})
app.get('/app/login', (c) => {
  setFromAppCookie(c)
  const errorMessage = c.req.query('error')
  const redirect = c.req.query('redirect')
  return c.render(renderLoginPage(errorMessage, redirect), { title: '소셜 로그인 - Web App' })
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
            class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
            placeholder="이메일"
          />
          <input
            type="password"
            name="password"
            required
            class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
            placeholder="비밀번호 (6-32자)"
          />
          <input
            type="password"
            name="confirm_password"
            required
            class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
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

    setCookie(
      c,
      'user_session',
      JSON.stringify(userSession),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
    )
    setFromAppCookie(c)

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
  const redirectTo = String(body.redirect || '').trim()

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

    setCookie(
      c,
      'user_session',
      JSON.stringify(userSession),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
    )
    setFromAppCookie(c)

    if ((dbUser.email as string) === 'admin@gomawo.app') {
      setCookie(
        c,
        'admin_force_setup',
        '1',
        withPublicCookieDomain(c.req.url, {
        path: '/',
        httpOnly: true,
        secure: false,
        maxAge: 60 * 10,
        sameSite: 'Lax',
      })
      )
    }

    const safeRedirect = redirectTo && redirectTo.startsWith('/') && !redirectTo.includes('//') ? redirectTo : '/dashboard'
    return c.redirect(safeRedirect)
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
  const reqMeta = new URL(c.req.url)
  const isHttps = reqMeta.protocol === 'https:'
  setCookie(
    c,
    'apple_oauth_state',
    state,
    withPublicCookieDomain(c.req.url, {
    path: '/',
    httpOnly: true,
      secure: isHttps,
    maxAge: 60 * 10,
      sameSite: isHttps ? 'None' : 'Lax',
  })
  )

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
    let sessionName = name

    if (existingUser) {
      userId = existingUser.id as number
      coupleId = existingUser.couple_id as number | null
      gender = existingUser.gender as string | null
      notificationTime = existingUser.notification_time as string || '20:00'
      isAdmin = (existingUser.is_admin as number | null) === 1

      // 사용자가 직접 수정한 닉네임은 소셜 재로그인 시 덮어쓰지 않는다.
      await c.env.DB.prepare(
        'UPDATE users SET email = ? WHERE id = ?'
      ).bind(email, userId).run()
      sessionName = (existingUser.name as string | null) || name

      coupleCode = await getCoupleCode(c.env.DB, coupleId)
    } else {
      const result = await c.env.DB.prepare(
        'INSERT INTO users (apple_id, email, name, picture) VALUES (?, ?, ?, ?)'
      ).bind(appleId, email, name, '').run()
      userId = result.meta.last_row_id as number
      sessionName = name
    }

    const setupDone = !!(gender && notificationTime && sessionName && sessionName !== 'Apple 사용자')
    const userSession: User = {
      id: appleId,
      db_id: userId,
      email,
      name: sessionName,
      picture: '',
      provider: 'apple',
      couple_id: coupleId,
      couple_code: coupleCode,
      gender,
      notification_time: notificationTime,
      is_admin: isAdmin,
      setup_done: setupDone
    }

    setCookie(
      c,
      'user_session',
      JSON.stringify(userSession),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
    )
    setFromAppCookie(c)

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
    'SELECT name, gender, notification_time, couple_id, promise_pending FROM users WHERE id = ?'
  ).bind(user.db_id).first() as { name?: string; gender?: string; notification_time?: string; couple_id?: number; promise_pending?: number } | null

  // 상대방이 연동했을 때 상대방 앱에서 우리의 약속 표시 (promise_pending)
  try {
    const pending = dbUser?.promise_pending
    if (pending === 1) {
      await c.env.DB.prepare('UPDATE users SET promise_pending = 0 WHERE id = ?').bind(user.db_id).run()
      return c.redirect('/dashboard?show_promise=1&from_link=1')
    }
  } catch (e) { /* promise_pending 컬럼 없을 수 있음 */ }

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
  
  const host = new URL(c.req.url).hostname
  const isLocal = host === 'localhost' || host === '127.0.0.1'
  
  return c.render(
    <div class="min-h-screen" style="background: var(--app-bg);">
      {isLocal && (
        <div class="bg-amber-500 text-white text-center py-1 text-sm font-medium">🖼️ 보드 포함 (로컬)</div>
      )}
      {/* 상단 헤더 - 서약서 보기 */}
      <div class="max-w-md mx-auto px-4 pt-6 pb-2 flex justify-end items-center">
        <div class="flex items-center gap-2">
          <button id="show-pledge-btn" class="p-2.5 rounded-full bg-white shadow-md hover:shadow-lg transition-all hover:scale-105 text-xl" title="우리의 곰아워 계약사항 다시 보기">📝</button>
        </div>
      </div>
      {/* 메인 컨텐츠 */}
      <div class="max-w-md mx-auto px-4 pt-2 pb-6">
          {!isPartnerLinked && (
          <div class="mb-4 p-4 bg-amber-50 border-2 border-amber-200 rounded-2xl">
            <p class="text-sm text-gray-700 mb-3 text-center">
              커플 연동을 하면<br/>
              서로에게 남긴 곰아워 메세지를 같이 볼 수 있어요!
            </p>
            <a href="/settings" target="_self" class="block text-center px-6 py-2 bg-amber-400 text-white rounded-xl hover:bg-amber-500 transition font-semibold">
              당장 연동하기
            </a>
          </div>
        )}
        {/* 감사 카운터 + 만난 날 */}
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6">
          {metDate && (
            <p class="text-center text-gray-600 text-base mb-3">
              우리가 만난 지 <span class="text-xl font-bold text-amber-600" id="met-days-count">+0</span>일
            </p>
          )}
          <p class="text-center text-gray-700 text-base">
            이번 달엔 총 <span class="text-3xl font-bold text-amber-600 mx-1" id="gratitude-count">0</span>일 동안 함께 곰아워했어요
            <span class="ml-1">🧡</span>
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

      {/* 하단 네비게이션 - 대시보드 */}
      <nav class="fixed bottom-0 left-0 right-0 py-1.5 z-50" style="background: var(--tabbar-bg); padding-bottom: max(0.42rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-4">
          <div class="grid grid-cols-3 gap-0">
            <a href="/dashboard" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-calendar text-gray-900 text-lg"></i>
              </div>
            </a>
            <a href="/history" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-book text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/settings" target="_self" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-user text-gray-400 text-lg"></i>
              </div>
            </a>
          </div>
        </div>
      </nav>

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
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 transform transition-all">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-2xl font-bold text-amber-700">오늘의 고마움을 전해볼까요?</h3>
            <button id="close-modal" class="p-2 rounded-full hover:bg-amber-50 transition">
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

      {/* 🧸🐾 코인 누적 기록 모달 */}
      <div id="rewards-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full max-h-[85vh] flex flex-col overflow-hidden">
          <div class="px-6 pt-6 pb-4 border-b border-amber-200 flex items-center justify-between">
            <h3 class="text-xl font-bold flex items-center gap-2 text-amber-700">
              코인 누적 기록
            </h3>
            <button type="button" id="close-rewards-modal" class="p-2 rounded-full hover:bg-gray-100 transition cursor-pointer">
              <i class="fas fa-times text-gray-600"></i>
            </button>
          </div>
          <div id="rewards-history" class="flex-1 overflow-y-auto px-6 py-4 space-y-3 min-h-[120px]">
            <p class="text-center py-8 text-base text-amber-700">아직 기록이 없어요 🐻</p>
          </div>
          <div class="px-6 pb-6 pt-2">
            <button type="button" id="how-to-earn-btn" class="w-full py-3.5 rounded-2xl font-semibold transition cursor-pointer border border-amber-300 bg-amber-50 text-amber-700 flex items-center justify-center gap-2 hover:bg-amber-100">
              <span>💡</span> 어떻게 모아요?
            </button>
          </div>
        </div>
      </div>

      {/* 보상 안내 모달 */}
      <div id="rewards-guide-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[51] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full max-h-[90vh] overflow-y-auto">
          <div class="p-6">
            <div class="text-center mb-6">
              <span class="text-5xl">💛</span>
              <h3 class="text-xl font-bold mt-2 text-amber-700">보상 안내</h3>
            </div>
            <div class="space-y-4 text-sm">
              <div class="rounded-2xl p-4 border-2" style="background: #FFFBEB; border-color: #FDE68A;">
                <p class="font-bold mb-2" style="color: #B45309;">✨ 기본 보상</p>
                <p class="text-gray-700">혼자 곰아워 → +1</p>
                <p class="text-gray-700">둘이 함께 곰아워 → +4</p>
              </div>
              <div class="rounded-2xl p-4 border-2" style="background: #ECFDF5; border-color: #A7F3D0;">
                <p class="font-bold mb-2" style="color: #047857;">🌱 개인 streak</p>
                <p class="text-gray-700">3일 연속 → +10</p>
                <p class="text-gray-700">7일 연속 → +20</p>
                <p class="text-gray-700">14일 연속 → +40</p>
                <p class="text-gray-700">30일 연속 → +80</p>
              </div>
              <div class="rounded-2xl p-4 border-2" style="background: #FDF2F8; border-color: #FBCFE8;">
                <p class="font-bold mb-2" style="color: #BE185D;">💞 커플 streak</p>
                <p class="text-gray-700">3일 함께 → +15</p>
                <p class="text-gray-700">7일 함께 → +35</p>
                <p class="text-gray-700">14일 함께 → +60</p>
                <p class="text-gray-700">30일 함께 → +120</p>
              </div>
            </div>
            <button type="button" id="close-rewards-guide-modal" class="w-full mt-6 py-3.5 rounded-2xl font-bold text-white cursor-pointer shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인
            </button>
          </div>
        </div>
      </div>

      {/* 날짜별 메시지 보기 모달 */}
      <div id="day-message-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full overflow-hidden">
          <div class="px-5 pt-4 pb-3 text-center border-b border-amber-200">
            <p class="text-sm text-amber-700 font-semibold" id="day-message-title">날짜</p>
          </div>
          <div id="day-message-body" class="px-5 py-4 space-y-3 text-sm text-gray-800"></div>
          <button id="close-day-message-modal" class="w-full py-3 text-amber-700 font-semibold border-t border-amber-200 hover:bg-amber-50">
            확인
          </button>
        </div>
      </div>

      {/* 미확인 메시지 모달 */}
      <div id="unread-message-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[62] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full max-h-[80vh] flex flex-col overflow-hidden">
          <div class="px-5 py-4 border-b border-amber-200 flex items-center justify-between">
            <h3 class="text-base font-bold text-amber-700">🐻 아직 안 본 메세지가 있어요</h3>
            <button type="button" id="close-unread-modal" class="p-2 rounded-full hover:bg-gray-100">
              <i class="fas fa-times text-gray-600"></i>
            </button>
          </div>
          <div id="unread-message-list" class="px-5 py-4 overflow-y-auto space-y-3"></div>
          <p id="unread-message-summary" class="hidden px-5 pb-1 text-xs text-amber-700 text-center"></p>
          <div class="px-5 py-4 border-t border-amber-200">
            <button type="button" id="confirm-unread-modal" class="w-full py-3 rounded-xl font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인했어요
            </button>
          </div>
        </div>
      </div>
      <div id="no-message-reminder-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[62] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 text-center">
          <img id="no-message-reminder-image" src="/static/promise-note-bear-female.png" alt="bear" class="w-28 h-28 mx-auto mb-3 object-contain" />
          <h3 id="no-message-reminder-title" class="text-lg font-bold text-amber-700 mb-2">우리의 계약사항 잊지않았죠?</h3>
          <p id="no-message-reminder-text" class="text-sm text-gray-700 mb-5">삐지지 말기</p>
          <button type="button" id="close-no-message-reminder-modal" class="w-full py-3 rounded-xl font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            알겠어요!
          </button>
        </div>
      </div>

      {/* 약속 메모 모달 */}
      <div id="promise-note-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[62] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 w-full max-w-5xl h-[92vh] flex flex-col overflow-hidden">
          <div class="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
            <h3 class="text-lg font-bold text-amber-700">우리 둘만의 약속 메모</h3>
            <button type="button" id="close-promise-note-modal" class="p-2 rounded-full hover:bg-amber-50">
              <i class="fas fa-times text-gray-600"></i>
            </button>
          </div>
          <div class="px-5 py-4 border-b border-gray-100 space-y-3">
            <input type="text" id="promise-note-title" placeholder="제목" class="w-full px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400" />
            <div class="flex items-center gap-2">
              <label for="promise-note-priority" class="text-sm text-gray-600 whitespace-nowrap">우선순위</label>
              <select id="promise-note-priority" class="flex-1 px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400">
                <option value="5">★★★★★ (5)</option>
                <option value="4">★★★★☆ (4)</option>
                <option value="3" selected>★★★☆☆ (3)</option>
                <option value="2">★★☆☆☆ (2)</option>
                <option value="1">★☆☆☆☆ (1)</option>
              </select>
            </div>
            <textarea id="promise-note-content" rows="3" placeholder="내용" class="w-full px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400 resize-none"></textarea>
            <button type="button" id="save-promise-note-btn" class="w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              저장하기
            </button>
            <p id="promise-note-feedback" class="text-xs text-center hidden"></p>
          </div>
          <div class="px-5 py-3 border-b border-gray-100 flex items-center justify-end gap-2">
            <label for="promise-note-sort" class="text-xs text-gray-500">정렬</label>
            <select id="promise-note-sort" class="px-2.5 py-1.5 border border-amber-200 rounded-md text-xs focus:ring-2 focus:ring-amber-300 focus:border-amber-400">
              <option value="latest" selected>최신순</option>
              <option value="priority">별점순</option>
            </select>
          </div>
          <div id="promise-note-list" class="px-5 py-4 overflow-y-auto space-y-3 min-h-[120px]">
            <p class="text-sm text-gray-500 text-center py-6">저장된 메모가 없어요.</p>
          </div>
        </div>
      </div>

      {/* 앱 잠금 PIN 모달 */}
      <div id="pin-lock-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
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

      {/* 앱 온보딩 모달 - 설정 완료 후 서약서 전에 표시 */}
      <div id="onboarding-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[61] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 text-center border-4 border-amber-300">
          <img src="/static/onboarding-bears.png" alt="곰아워" class="w-40 h-40 mx-auto mb-4 object-contain" />
          <h3 class="text-xl font-bold text-amber-600 mb-6">🐻곰아워⏰ 사용법</h3>
          <div class="space-y-5 text-center mb-5">
            <div class="bg-amber-50 rounded-2xl p-4 border-2 border-amber-100">
              <p class="text-sm font-bold text-amber-600 mb-1">하루에 한 번</p>
              <p class="text-black font-bold mb-4">사랑하는 사람에게<br/>고마운 마음을 메세지에 담아 전달해보세요</p>
              <p class="text-sm font-bold text-amber-600 mb-1">잠들기 전에는</p>
              <p class="text-black font-bold">상대방이 보낸 메세지도 확인해보세요</p>
            </div>
            <div class="bg-orange-100 rounded-2xl p-4 border-2 border-orange-300">
              <p class="text-sm font-bold text-orange-700">⚠️ 꼭 오늘이 지나기 전에 메시지를 작성해야 해요</p>
            </div>
          </div>
          <button id="close-onboarding" class="w-full py-3 rounded-xl font-bold text-white text-base shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            숙지 완료했어요!
          </button>
        </div>
      </div>

      {/* 곰아워 약속 모달 - 설정 완료 후 첫 메인 진입 시 */}
      <div id="promise-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[60] flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl max-w-md w-full p-6 text-center border-4 border-amber-400">
          <img src="/static/promise-bears.png" alt="곰아워" class="w-32 h-32 mx-auto mb-4 object-contain" onerror="this.onerror=null;this.src='/static/bear-couple.png'" />
          <h3 class="text-xl font-bold text-gray-800 mb-2">우리의 곰아워 계약사항</h3>
          <p class="text-base text-gray-800 font-semibold mb-6">
            누가 더 자주 했는지보다,<br/>
            함께 마음을 나누고 있다는 게<br/>
            더 소중한 거 아시죠? 🧡
          </p>
          <div class="space-y-4 text-center mb-6 flex flex-col items-center">
            <label class="flex items-center justify-center gap-3 cursor-pointer">
              <input type="checkbox" id="promise-1" class="w-5 h-5 rounded border-2 border-amber-400 accent-amber-500 focus:ring-amber-400" />
              <span class="text-gray-800">곰아워 횟수로 사랑의 크기 재지 않기</span>
            </label>
            <label class="flex items-center justify-center gap-3 cursor-pointer">
              <input type="checkbox" id="promise-2" class="w-5 h-5 rounded border-2 border-amber-400 accent-amber-500 focus:ring-amber-400" />
              <span class="text-gray-800">내가 더 많이 했다고 삐치지 말기</span>
            </label>
            <label class="flex items-center justify-center gap-3 cursor-pointer">
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
          <h3 class="text-xl font-bold text-amber-700 mb-1">우리의 곰아워 계약사항</h3>
          <p class="text-base text-gray-800 font-semibold mb-5">
            누가 더 자주 했는지보다,<br/>
            함께 마음을 나누고 있다는 게<br/>
            더 소중한 거 아시죠? 🧡
          </p>
          <div class="space-y-3 text-center mb-6 bg-amber-50 rounded-2xl p-4 border-2 border-amber-100">
            <p class="flex items-center justify-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 곰아워 횟수로 사랑의 크기 재지 않기</p>
            <p class="flex items-center justify-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 내가 더 많이 했다고 삐치지 말기</p>
            <p class="flex items-center justify-center gap-2 text-gray-800"><i class="fas fa-check-circle text-amber-500"></i> 상대가 적게 해도 이해해주기</p>
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

          // 미확인 메시지 모달 (대시보드 진입 시 자동 표시)
          (function() {
            const modal = document.getElementById('unread-message-modal');
            const list = document.getElementById('unread-message-list');
            const unreadSummary = document.getElementById('unread-message-summary');
            const closeBtn = document.getElementById('close-unread-modal');
            const confirmBtn = document.getElementById('confirm-unread-modal');
            const noMsgModal = document.getElementById('no-message-reminder-modal');
            const noMsgImage = document.getElementById('no-message-reminder-image');
            const noMsgTitle = document.getElementById('no-message-reminder-title');
            const noMsgText = document.getElementById('no-message-reminder-text');
            const closeNoMsgBtn = document.getElementById('close-no-message-reminder-modal');
            if (!modal || !list) return;
            const escapeHtml = (str) => String(str || '')
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
            let currentUnreadIds = [];
            const closeModal = () => modal.classList.add('hidden');
            const closeNoMsgModal = () => { if (noMsgModal) noMsgModal.classList.add('hidden'); };
            if (closeBtn) closeBtn.addEventListener('click', closeModal);
            if (confirmBtn) {
              confirmBtn.addEventListener('click', function() {
                const ids = currentUnreadIds.slice();
                if (ids.length > 0) {
                  window.__markMessagesRead(ids);
                }
                closeModal();
              });
            }
            if (closeNoMsgBtn) closeNoMsgBtn.addEventListener('click', closeNoMsgModal);
            modal.addEventListener('click', function(e) {
              if (e.target === modal) closeModal();
            });
            if (noMsgModal) {
              noMsgModal.addEventListener('click', function(e) {
                if (e.target === noMsgModal) closeNoMsgModal();
              });
            }
            window.__markMessagesRead = function(ids) {
              if (!Array.isArray(ids) || ids.length === 0) return;
              fetch('/api/messages/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ message_ids: ids })
              }).catch(function() {});
            };
            const showNoMessageHint = (hint) => {
              if (!hint || !noMsgModal || !noMsgImage || !noMsgTitle || !noMsgText) return;
              const gender = hint.partner_gender === 'male' ? 'male' : 'female';
              noMsgImage.src = gender === 'male' ? '/static/promise-note-bear-male.png' : '/static/promise-note-bear-female.png';
              noMsgTitle.textContent = '우리의 계약사항 잊지않았죠?';
              noMsgText.textContent = '삐지지 말기';
              noMsgModal.classList.remove('hidden');
            };
            fetch('/api/messages/unread', { credentials: 'include' })
              .then((r) => r.json())
              .then((res) => {
                if (!res || !res.success || !Array.isArray(res.unread_messages)) return;
                if (res.unread_messages.length > 0) {
                  currentUnreadIds = res.unread_messages
                    .map(function(item) { return Number(item.id); })
                    .filter(function(id) { return Number.isInteger(id) && id > 0; });
                  if (unreadSummary) {
                    const total = Number(res.unread_total_count || res.unread_messages.length);
                    if (total > res.unread_messages.length) {
                      unreadSummary.textContent = '최근 ' + res.unread_messages.length + '개만 먼저 보여드려요. 기록 탭에서 모두 확인할 수 있어요.';
                      unreadSummary.classList.remove('hidden');
                    } else {
                      unreadSummary.classList.add('hidden');
                    }
                  }
                  list.innerHTML = res.unread_messages.map((item) => {
                    const author = escapeHtml(item.name || '상대방');
                    const date = escapeHtml(item.message_date || '');
                    const content = escapeHtml(item.content || '');
                    return '<div class="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3">' +
                      '<div class="text-xs text-gray-500 mb-1">' + date + ' · ' + author + '</div>' +
                      '<p class="text-sm text-gray-800 whitespace-pre-wrap">' + content + '</p>' +
                    '</div>';
                  }).join('');
                  modal.classList.remove('hidden');
                  return;
                }
                currentUnreadIds = [];
                if (res.empty_hint) {
                  showNoMessageHint(res.empty_hint);
                }
              })
              .catch(function() {});
          })();

          // 약속 메모 모달
          (function() {
            const openBtn = document.getElementById('show-promise-note-btn');
            const modal = document.getElementById('promise-note-modal');
            const closeBtn = document.getElementById('close-promise-note-modal');
            const saveBtn = document.getElementById('save-promise-note-btn');
            const titleInput = document.getElementById('promise-note-title');
            const priorityInput = document.getElementById('promise-note-priority');
            const contentInput = document.getElementById('promise-note-content');
            const sortSelect = document.getElementById('promise-note-sort');
            const listEl = document.getElementById('promise-note-list');
            const feedbackEl = document.getElementById('promise-note-feedback');
            if (!openBtn || !modal || !saveBtn || !titleInput || !priorityInput || !contentInput || !sortSelect || !listEl || !feedbackEl) return;
            let noteCache = [];
            let editingNoteId = null;
            let deletingNoteId = null;

            const escapeHtml = (str) => String(str || '')
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
            const resetNoteForm = () => {
              editingNoteId = null;
              titleInput.value = '';
              priorityInput.value = '3';
              contentInput.value = '';
            };

            const renderStars = (priority) => {
              const p = Math.max(1, Math.min(5, Number(priority || 3)));
              return '★'.repeat(p) + '☆'.repeat(5 - p);
            };

            function showFeedback(msg, isError) {
              feedbackEl.textContent = msg;
              feedbackEl.className = 'text-xs text-center ' + (isError ? 'text-red-600' : 'text-green-600');
              feedbackEl.classList.remove('hidden');
            }

            async function loadPromiseNotes() {
              try {
                const sortBy = sortSelect.value === 'priority' ? 'priority' : 'latest';
                const res = await fetch('/api/promise-notes?sort_by=' + encodeURIComponent(sortBy), { credentials: 'include' });
                const data = await res.json();
                if (!data.success) {
                  showFeedback(data.error || '메모를 불러오지 못했어요.', true);
                  return;
                }
                const notes = Array.isArray(data.notes) ? data.notes : [];
                noteCache = notes;
                if (notes.length === 0) {
                  listEl.innerHTML = '<p class="text-sm text-gray-500 text-center py-6">저장된 메모가 없어요.</p>';
                  return;
                }
                listEl.innerHTML = notes.map((note) => {
                  const noteId = String(note.id || '');
                  const title = escapeHtml(note.title || '');
                  const stars = renderStars(note.priority || 3);
                  const noteDate = escapeHtml((note.note_date || note.created_at || '').slice(0, 10));
                  const content = escapeHtml(note.content || '');
                  const author = escapeHtml(note.author_name || '우리');
                  return '<div class="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 relative">' +
                    '<div class="absolute top-2.5 right-2.5 flex items-center gap-1">' +
                      '<button type="button" class="promise-note-edit-btn w-7 h-7 rounded-full border border-amber-300 text-amber-700 hover:bg-amber-100 text-xs flex items-center justify-center" data-note-id="' + noteId + '" aria-label="메모 수정">' +
                        '<i class="fas fa-pen"></i>' +
                      '</button>' +
                      '<button type="button" class="promise-note-delete-btn w-7 h-7 rounded-full border border-red-300 text-red-600 hover:bg-red-50 text-xs flex items-center justify-center" data-note-id="' + noteId + '" aria-label="메모 삭제">' +
                        '<i class="fas fa-trash"></i>' +
                      '</button>' +
                    '</div>' +
                    '<p class="text-sm font-bold text-gray-800 pr-16 mb-1">' + title + '</p>' +
                    '<p class="text-xs text-amber-500 font-semibold mb-1">' + stars + '</p>' +
                    '<p class="text-xs text-gray-500 mb-2">작성: ' + author + '</p>' +
                    '<p class="text-sm text-gray-700 whitespace-pre-wrap">' + content + '</p>' +
                    '<p class="text-xs text-gray-500 mt-2">' + noteDate + '</p>' +
                  '</div>';
                }).join('');
              } catch (_) {
                showFeedback('메모를 불러오는 중 오류가 발생했어요.', true);
              }
            }

            function openModal() {
              modal.classList.remove('hidden');
              feedbackEl.classList.add('hidden');
              resetNoteForm();
              loadPromiseNotes();
            }

            function closeModal() {
              modal.classList.add('hidden');
            }

            openBtn.addEventListener('click', openModal);
            if (closeBtn) closeBtn.addEventListener('click', closeModal);
            modal.addEventListener('click', function(e) { if (e.target === modal) closeModal(); });
            listEl.addEventListener('click', async function(e) {
              const target = e.target;
              if (!(target instanceof HTMLElement)) return;
              const editBtn = target.closest('.promise-note-edit-btn');
              if (editBtn) {
                const noteId = editBtn.getAttribute('data-note-id');
                const note = noteCache.find((item) => String(item.id) === String(noteId));
                if (!note) return;
                editingNoteId = Number(note.id);
                titleInput.value = String(note.title || '');
                priorityInput.value = String(note.priority || 3);
                contentInput.value = String(note.content || '');
                feedbackEl.classList.add('hidden');
                titleInput.focus();
                return;
              }
              const deleteBtn = target.closest('.promise-note-delete-btn');
              if (!deleteBtn) return;
              const noteId = deleteBtn.getAttribute('data-note-id');
              if (!noteId || deletingNoteId === noteId) return;
              deletingNoteId = noteId;
              deleteBtn.setAttribute('disabled', 'true');
              try {
                const res = await fetch('/api/promise-notes/' + noteId, {
                  method: 'DELETE',
                  credentials: 'include',
                });
                const data = await res.json();
                if (!data.success) {
                  showFeedback(data.error || '삭제에 실패했어요.', true);
                  return;
                }
                if (editingNoteId === Number(noteId)) {
                  resetNoteForm();
                }
                showFeedback('약속 메모를 삭제했어요.', false);
                await loadPromiseNotes();
              } catch (_) {
                showFeedback('삭제 중 오류가 발생했어요.', true);
              } finally {
                deletingNoteId = null;
                deleteBtn.removeAttribute('disabled');
              }
            });

            saveBtn.addEventListener('click', async function() {
              const title = titleInput.value.trim();
              const priority = Number(priorityInput.value || 3);
              const content = contentInput.value.trim();
              if (!title || !content) {
                showFeedback('제목과 내용을 모두 입력해주세요.', true);
                return;
              }
              if (!Number.isInteger(priority) || priority < 1 || priority > 5) {
                showFeedback('우선순위는 1~5 사이로 선택해주세요.', true);
                return;
              }
              try {
                const isEdit = Number.isInteger(editingNoteId) && editingNoteId > 0;
                const endpoint = isEdit ? '/api/promise-notes/' + editingNoteId : '/api/promise-notes';
                const method = isEdit ? 'PUT' : 'POST';
                const res = await fetch(endpoint, {
                  method: method,
                  headers: { 'Content-Type': 'application/json' },
                  credentials: 'include',
                  body: JSON.stringify({ title: title, priority: priority, content: content }),
                });
                const data = await res.json();
                if (!data.success) {
                  showFeedback(data.error || '저장에 실패했어요.', true);
                  return;
                }
                showFeedback(isEdit ? '약속 메모를 수정했어요.' : '약속 메모를 저장했어요.', false);
                resetNoteForm();
                await loadPromiseNotes();
              } catch (_) {
                showFeedback('저장 중 오류가 발생했어요.', true);
              }
            });
            sortSelect.addEventListener('change', function() { loadPromiseNotes(); });
          })();
          
          // 서약서 다시 보기 버튼
          (function() {
            const showBtn = document.getElementById('show-pledge-btn');
            const pledgeModal = document.getElementById('pledge-view-modal');
            const closeBtn = document.getElementById('close-pledge-view');
            if (showBtn && pledgeModal) {
              showBtn.addEventListener('click', () => pledgeModal.classList.remove('hidden'));
            }
            if (closeBtn && pledgeModal) {
              closeBtn.addEventListener('click', () => { pledgeModal.classList.add('hidden'); history.replaceState({}, '', '/dashboard'); });
            }
            if (pledgeModal) {
              pledgeModal.addEventListener('click', (e) => { if (e.target === pledgeModal) { pledgeModal.classList.add('hidden'); history.replaceState({}, '', '/dashboard'); } });
            }
            // 연동 완료 후 우리의 약속 표시 (마이페이지에서 연동 시)
            const params = new URLSearchParams(window.location.search);
            if (params.get('from_link') === '1' && params.get('show_promise') === '1' && pledgeModal) {
              pledgeModal.classList.remove('hidden');
            }
          })();
          
          // 앱 온보딩 모달 - from_setup=1일 때 서약서 전에 먼저 표시
          (function() {
            const params = new URLSearchParams(window.location.search);
            if (params.get('from_setup') !== '1' || params.get('show_promise') !== '1') return;
            const onboardingModal = document.getElementById('onboarding-modal');
            const promiseModal = document.getElementById('promise-modal');
            const closeOnboarding = document.getElementById('close-onboarding');
            if (!onboardingModal || !promiseModal || !closeOnboarding) return;
            onboardingModal.classList.remove('hidden');
            closeOnboarding.addEventListener('click', function() {
              onboardingModal.classList.add('hidden');
              promiseModal.classList.remove('hidden');
            });
            onboardingModal.addEventListener('click', function(e) {
              if (e.target === onboardingModal) {
                onboardingModal.classList.add('hidden');
                promiseModal.classList.remove('hidden');
              }
            });
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
            // from_setup=1이면 온보딩이 먼저 표시되므로 여기서는 표시하지 않음 (온보딩 닫을 때 표시됨)
            if (params.get('from_setup') === '1') return;
            modal.classList.remove('hidden');
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

          const __readMarkSent = new Set();
          function getPartnerMessageIds(dayMessages) {
            if (!dayMessages) return [];
            const ids = [];
            if (currentUser.gender === 'male') {
              if (dayMessages.female && dayMessages.female.id) ids.push(dayMessages.female.id);
            } else if (currentUser.gender === 'female') {
              if (dayMessages.male && dayMessages.male.id) ids.push(dayMessages.male.id);
            } else {
              if (dayMessages.male && dayMessages.male.id) ids.push(dayMessages.male.id);
              if (dayMessages.female && dayMessages.female.id) ids.push(dayMessages.female.id);
            }
            return ids;
          }
          async function markMessagesAsReadByIds(ids) {
            if (!Array.isArray(ids) || ids.length === 0) return;
            const key = ids.slice().sort((a, b) => a - b).join(',');
            if (__readMarkSent.has(key)) return;
            __readMarkSent.add(key);
            try {
              await fetch('/api/messages/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ message_ids: ids })
              });
            } catch (_) {
              __readMarkSent.delete(key);
            }
          }
          async function markPartnerMessagesAsRead(dayMessages) {
            const ids = getPartnerMessageIds(dayMessages);
            if (ids.length === 0) return;
            await markMessagesAsReadByIds(ids);
          }

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

          // 곰발바닥 코인 불러오기
          let rewardsData = { totalCoins: 0, history: [] };
          async function loadRewards() {
            try {
              const res = await fetch('/api/rewards/summary', { credentials: 'include' });
              const data = await res.json();
              if (data.success) {
                rewardsData = { totalCoins: data.totalCoins || 0, history: data.history || [] };
                const el = document.getElementById('coin-count');
                if (el) el.textContent = String(rewardsData.totalCoins);
              }
            } catch (e) { console.error('보상 로드 실패:', e); }
          }
          loadRewards();

          // 코인 버튼 클릭 → 누적 기록 모달
          (function(){
            var coinBtn = document.getElementById('coin-btn');
            var closeBtn = document.getElementById('close-rewards-modal');
            var modal = document.getElementById('rewards-modal');
            var historyEl = document.getElementById('rewards-history');
            if (coinBtn && modal && historyEl) {
              coinBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (rewardsData.history.length === 0) {
                  historyEl.innerHTML = '<p class="text-center text-amber-600 py-8">아직 기록이 없어요 🐻</p>';
                } else {
                  historyEl.innerHTML = rewardsData.history.map(function(h) {
                    var bg = h.type === 'streak_individual'
                      ? 'bg-green-50 border-green-200'
                      : (h.type === 'streak_couple'
                        ? 'bg-pink-50 border-pink-200'
                        : ((h.type === 'jackpot_quote' || h.type === 'care_mission')
                          ? 'bg-orange-50 border-orange-200'
                          : 'bg-amber-50 border-amber-100'));
                    var icon = h.type === 'streak_individual' ? '🌱' : (h.type === 'streak_couple' ? '💞' : (h.type === 'jackpot_quote' ? '🕊️' : (h.type === 'care_mission' ? '💌' : '✨')));
                    var rawLabel = String(h.label || '');
                    var label = h.type === 'jackpot_quote'
                      ? rawLabel
                      : rawLabel.replace(/^[\u{1F300}-\u{1FAFF}\u2600-\u27BF]+\s*/u, '');
                    label = label.replace(/\\s[+-]\\d+(?:코인)?\\s*$/u, '').trim();
                    return '<div class="py-2.5 px-4 rounded-2xl ' + bg + ' border text-sm text-gray-800">' + icon + ' ' + label + '</div>';
                  }).join('');
                }
                modal.classList.remove('hidden');
              });
            }
            if (closeBtn && modal) closeBtn.addEventListener('click', function(e) { e.preventDefault(); modal.classList.add('hidden'); });
            var howToBtn = document.getElementById('how-to-earn-btn');
            var guideModal = document.getElementById('rewards-guide-modal');
            var closeGuideBtn = document.getElementById('close-rewards-guide-modal');
            if (howToBtn && guideModal) howToBtn.addEventListener('click', function(e) { e.preventDefault(); e.stopPropagation(); guideModal.classList.remove('hidden'); });
            if (closeGuideBtn && guideModal) closeGuideBtn.addEventListener('click', function(e) { e.preventDefault(); guideModal.classList.add('hidden'); });
          })();

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
                  markPartnerMessagesAsRead(dayMessages);
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
                if (typeof loadRewards === 'function') loadRewards();
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
    deleteCookie(c, 'admin_force_setup', withPublicCookieDomain(c.req.url, { path: '/' }))
  }

  return c.render(
    <div class="min-h-screen" style="background: var(--app-bg);">
      <div class="max-w-md mx-auto px-4 py-8">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 p-8">
          <div class="text-center mb-8">
            <p class="text-lg font-bold text-gray-800">
              설정을 완료하고,<br/>
              연인과 함께 곰아워 메세지를 나눠보세요
            </p>
          </div>

          {/* 닉네임 설정 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">닉네임</label>
            <input 
              type="text" 
              id="nickname-input"
              value={user.email === 'admin@gomawo.app' ? '' : (user.name && user.name !== 'Apple 사용자' && user.name !== '이메일 사용자' ? user.name : '')}
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400"
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

          {/* 커플 연동 - 항상 표시 */}
          <div class="mb-6">
            <label class="block text-sm font-bold text-gray-700 mb-3">커플 연동</label>
            <input 
              type="text" 
              id="couple-code-input"
              placeholder="상대방 코드를 입력하세요"
              maxlength="6"
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400 text-center text-2xl font-bold uppercase mb-4"
            />
            <button id="join-couple-btn" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all mb-4" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              연동하기
              </button>
              
            <form id="skip-setup-form" method="post" action="/setup/skip" target="_self" enctype="application/x-www-form-urlencoded" style="display:none">
              <input type="hidden" name="name" id="skip-form-name" value="" />
              <input type="hidden" name="gender" id="skip-form-gender" value="" />
              <input type="hidden" name="notification_time" id="skip-form-time" value="" />
            </form>
            <button type="button" id="skip-setup-btn" class="w-full py-3 rounded-xl font-bold text-lg shadow-lg hover:shadow-xl transition-all text-center text-gray-600 bg-gray-200 hover:bg-gray-300 border-0">
              나중에 연동하기
              </button>
                </div>
            </div>
          </div>

      {/* 잘못된 코드 모달 */}
      <div id="setup-wrong-code-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 text-center">
          <p class="text-lg text-gray-800 mb-6">잘못된 코드입니다.</p>
          <button type="button" onclick="document.getElementById('setup-wrong-code-modal').classList.add('hidden')" class="w-full py-3 rounded-xl font-bold text-white text-base cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            확인
              </button>
            </div>
          </div>

      {/* 닉네임/성별 설정 필요 모달 */}
      <div id="setup-required-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 text-center">
          <p class="text-lg text-gray-800 mb-6">닉네임과 성별을 먼저 설정해주세요.</p>
          <button type="button" onclick="document.getElementById('setup-required-modal').classList.add('hidden')" class="w-full py-3 rounded-xl font-bold text-white text-base cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            확인
            </button>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          let selectedGender = null;
          
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
          
          // 커플 연동
          document.getElementById('join-couple-btn').addEventListener('click', async () => {
            const nickname = document.getElementById('nickname-input').value.trim();
            if (!nickname || !selectedGender) {
              document.getElementById('setup-required-modal').classList.remove('hidden');
              return;
            }
            
            const coupleCode = document.getElementById('couple-code-input').value.trim().toUpperCase();
            if (!coupleCode || coupleCode.length !== 6) {
              document.getElementById('setup-wrong-code-modal').classList.remove('hidden');
              return;
            }
            
            const notificationTime = '20:00';
            
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
              const target = (window.location.origin || '') + '/dashboard?show_promise=1&from_setup=1';
              window.location.replace(target);
            } else {
              document.getElementById('setup-wrong-code-modal').classList.remove('hidden');
            }
          });

          // 나중에 하기 버튼 - fetch 우선, 실패 시 폼 제출 (WebView 호환)
          document.getElementById('skip-setup-btn').addEventListener('click', async function() {
            const nickname = document.getElementById('nickname-input').value.trim();
            if (!nickname || !selectedGender) {
              document.getElementById('setup-required-modal').classList.remove('hidden');
              return;
            }
            const notificationTime = '20:00';
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
    <div class="min-h-screen pb-24" style="background: var(--app-bg);">
      <div class="max-w-md mx-auto px-4 py-6">
        {/* 헤더 */}
        <div class="history-title-row flex items-center justify-center mb-6">
          <h1 class="text-2xl font-bold text-gray-800">
            우리의 곰아워 메세지들
          </h1>
        </div>
        <style>{`
          .history-title-row img { display: none !important; }
        `}</style>

        {/* 년도/월 선택 */}
        <div class="flex items-center justify-center gap-4 mb-6">
          <select id="year-select" class="px-4 py-2 border-2 border-gray-300 rounded-xl bg-white focus:ring-2 focus:ring-gray-300 focus:border-gray-300">
            <option value="2024">2024년</option>
            <option value="2025">2025년</option>
            <option value="2026" selected>2026년</option>
          </select>
          <select id="month-select" class="px-4 py-2 border-2 border-gray-300 rounded-xl bg-white focus:ring-2 focus:ring-gray-300 focus:border-gray-300">
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

      {/* 하단 네비게이션 - 자세히보기 */}
      <nav class="fixed bottom-0 left-0 right-0 py-1.5 z-50" style="background: var(--tabbar-bg); padding-bottom: max(0.42rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-4">
          <div class="grid grid-cols-3 gap-0">
            <a href="/dashboard" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-calendar text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/history" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-book text-gray-900 text-lg"></i>
              </div>
            </a>
            <a href="/settings" target="_self" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-user text-gray-400 text-lg"></i>
              </div>
            </a>
          </div>
        </div>
      </nav>

      <script dangerouslySetInnerHTML={{
        __html: `
          const currentUser = ${JSON.stringify(user)};
          const today = new Date();
          let currentYear = today.getFullYear();
          let currentMonth = today.getMonth() + 1;

          const __historyReadSent = new Set();
          function getPartnerMessageIdsForHistoryDay(dayMessages) {
            if (!dayMessages) return [];
            const ids = [];
            const g = String(currentUser && currentUser.gender || '').trim();
            if (g === 'male') {
              if (dayMessages.female && dayMessages.female.id) ids.push(Number(dayMessages.female.id));
            } else if (g === 'female') {
              if (dayMessages.male && dayMessages.male.id) ids.push(Number(dayMessages.male.id));
            } else {
              if (dayMessages.male && dayMessages.male.id) ids.push(Number(dayMessages.male.id));
              if (dayMessages.female && dayMessages.female.id) ids.push(Number(dayMessages.female.id));
            }
            return ids.filter(function(id) { return Number.isInteger(id) && id > 0; });
          }
          function markHistoryMessagesRead(ids) {
            if (!Array.isArray(ids) || ids.length === 0) return;
            const fresh = ids.filter(function(id) { return id > 0 && !__historyReadSent.has(id); });
            fresh.forEach(function(id) { __historyReadSent.add(id); });
            if (!fresh.length) return;
            fetch('/api/messages/read', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify({ message_ids: fresh })
            }).catch(function() {
              fresh.forEach(function(id) { __historyReadSent.delete(id); });
            });
          }
          function collectPartnerMessageIdsForHistoryMonth(messagesData) {
            const out = [];
            const seen = new Set();
            Object.keys(messagesData || {}).forEach(function(key) {
              getPartnerMessageIdsForHistoryDay(messagesData[key]).forEach(function(id) {
                if (!seen.has(id)) {
                  seen.add(id);
                  out.push(id);
                }
              });
            });
            return out;
          }

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
              const weekdayKr = ['일', '월', '화', '수', '목', '금', '토'];
              const weekday = weekdayKr[dateObj.getDay()];
              const [year, month, day] = date.split('-');
              const messageCard = document.createElement('div');
              messageCard.className = 'bg-white rounded-3xl shadow-lg p-6 cursor-pointer hover:ring-2 hover:ring-amber-200 transition';
              
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
            markHistoryMessagesRead(collectPartnerMessageIdsForHistoryMonth(messagesData));
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

// 잭팟 페이지 (기존 마이페이지 탭)
app.get('/mypage', async (c) => {
  return c.redirect('/settings')
})

app.get('/settings', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.redirect('/app/login')

  if (!user.gender || !user.notification_time) {
    return c.redirect('/setup')
  }

  return c.render(
    <div class="min-h-screen pb-28" style="background: var(--app-bg);">
      <div class="max-w-md mx-auto px-4 py-6">
        <div class="relative h-11 mb-3 flex items-center justify-center">
          <button id="coin-btn" type="button" class="absolute left-0 settings-menu-item flex items-center gap-2 py-2 px-3 rounded-xl bg-white shadow-md hover:shadow-lg transition-all cursor-pointer">
            <img src="/static/coin-bear-paw.png" alt="곰발바닥" class="w-8 h-8 object-contain" />
            <span id="coin-count" class="text-base font-bold text-amber-700">0</span>
            <span class="text-sm text-gray-600">개</span>
          </button>
          <p class="text-2xl leading-none font-extrabold text-black tracking-wide">마이페이지</p>
          <div class="absolute right-0 flex items-center gap-2">
            <button id="show-promise-note-btn" type="button" class="p-2.5 rounded-full bg-white shadow-md hover:shadow-lg transition-all hover:scale-105 text-xl" title="약속 메모">📒</button>
            <button id="open-settings-side-modal" type="button" class="p-2.5 rounded-full bg-white shadow-md hover:shadow-lg transition-all hover:scale-105 text-xl">
              ⚙️
            </button>
          </div>
        </div>

        <div class="bg-white rounded-3xl shadow-lg p-5 mb-5 border-2 border-amber-200">
          <div class="flex items-center justify-between mb-1">
            <div class="flex items-center">
              <h1 class="text-lg font-bold text-gray-800">🎰 사랑의 글귀</h1>
              <button id="jackpot-info-btn" class="ml-2 text-xs font-semibold text-amber-600 hover:text-amber-700" type="button">i</button>
            </div>
            <button id="open-saved-quotes-btn" class="px-3 py-1.5 rounded-lg border border-amber-300 text-amber-700 text-xs font-semibold bg-amber-50 hover:bg-amber-100" type="button">
              저장한 글귀
            </button>
          </div>
            <div class="mt-4 rounded-2xl border-2 border-amber-300 bg-gradient-to-b from-amber-100 to-amber-50 p-3.5 pb-5 shadow-inner overflow-hidden relative">
            <style>{`
              .jackpot-slot-frame {
                transition: box-shadow 180ms ease;
              }
              .jackpot-slot-frame.jackpot-shake {
                animation: jackpot-shake 420ms ease;
                box-shadow: 0 0 0 2px rgba(251, 191, 36, 0.25) inset;
              }
              .jackpot-reveal {
                animation: jackpot-reveal 360ms ease;
              }
              .jackpot-reel.jackpot-spin {
                animation: jackpot-reel-spin 780ms cubic-bezier(0.16, 1, 0.3, 1);
                transform-origin: center center;
              }
              .jackpot-lever-pop {
                animation: jackpot-lever-pop 260ms ease;
              }
              @keyframes jackpot-shake {
                0% { transform: translateX(0); }
                20% { transform: translateX(-2px); }
                40% { transform: translateX(2px); }
                60% { transform: translateX(-1px); }
                80% { transform: translateX(1px); }
                100% { transform: translateX(0); }
              }
              @keyframes jackpot-reveal {
                0% { opacity: 0; transform: translateY(10px) scale(0.96) rotate(-1.5deg); filter: blur(1px); }
                100% { opacity: 1; transform: translateY(0) scale(1) rotate(0deg); filter: blur(0); }
              }
              @keyframes jackpot-reel-spin {
                0% { transform: rotate(0deg) scale(1); filter: blur(0); opacity: 1; }
                20% { transform: rotate(-18deg) scale(0.97); filter: blur(3px); opacity: 0.86; }
                40% { transform: rotate(22deg) scale(0.95); filter: blur(3.8px); opacity: 0.8; }
                60% { transform: rotate(-15deg) scale(0.965); filter: blur(2.5px); opacity: 0.88; }
                80% { transform: rotate(8deg) scale(0.985); filter: blur(1.2px); opacity: 0.95; }
                100% { transform: rotate(0deg) scale(1); filter: blur(0); opacity: 1; }
              }
              @keyframes jackpot-lever-pop {
                0% { transform: translateY(0); }
                40% { transform: translateY(2px); }
                100% { transform: translateY(0); }
              }
            `}</style>
            <div class="flex items-stretch gap-3 pt-1">
              <div id="jackpot-slot-frame" class="jackpot-slot-frame relative flex-1 h-44 rounded-xl border border-amber-200 bg-white overflow-hidden">
                <div id="jackpot-reel" class="jackpot-reel absolute inset-0">
                  <div id="jackpot-empty-slot" class="absolute inset-0 flex items-center justify-center p-6 text-center">
                    <p class="text-sm text-gray-500">오른쪽 레버를 당겨주세요.</p>
                  </div>
                  <div id="jackpot-quote-card" class="hidden absolute inset-0 p-3.5">
                    <div class="h-full relative">
                      <button id="jackpot-save-btn" class="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 flex items-center justify-center shadow-sm" title="글귀 저장" type="button">
                        <i class="fas fa-heart"></i>
                      </button>
                      <div class="h-full flex flex-col items-center justify-center text-center px-2">
                        <p id="jackpot-quote-text" class="text-[15px] text-gray-800 leading-relaxed whitespace-pre-wrap"></p>
                        <p id="jackpot-quote-source" class="text-[12px] text-gray-500 mt-1"></p>
                        <p id="jackpot-quote-inline" class="hidden text-[15px] text-gray-800 leading-relaxed whitespace-pre-wrap">
                          <span id="jackpot-quote-inline-text"></span>
                          <span id="jackpot-quote-inline-source" class="text-[12px] text-gray-500 ml-1"></span>
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="w-10 flex items-center justify-center">
                <div id="jackpot-lever-base" class="relative h-24 w-10 flex items-center justify-center touch-none select-none">
                  <div id="jackpot-lever-track" class="absolute top-1 bottom-1 w-2 rounded-full bg-gradient-to-b from-gray-100 via-gray-300 to-gray-400 border border-gray-300 shadow-inner touch-none"></div>
                  <div id="jackpot-lever-knob" class="absolute top-0 w-6 h-6 rounded-full shadow-lg border border-rose-500 bg-gradient-to-br from-rose-300 via-rose-500 to-rose-700 touch-none">
                    <div class="absolute top-1 left-1 w-2 h-2 rounded-full bg-white/60"></div>
                  </div>
                </div>
              </div>
            </div>
            <p id="jackpot-draw-meta" class="absolute right-3 bottom-[3px] text-[10px] text-gray-500 text-right"></p>
          </div>
          <p id="jackpot-status" class="text-xs text-center text-gray-500 mt-[14px]">레버를 당겨 랜덤 글귀를 받아보세요.</p>
        </div>

        <div class="bg-white rounded-3xl shadow-lg p-5 mb-5 border-2 border-amber-200">
          <div class="flex items-center justify-between mb-2">
            <div class="flex items-center gap-1.5">
              <h2 class="text-lg font-bold text-gray-800">💌 사랑의 언어 미션</h2>
              <button id="open-love-mission-info-modal" class="text-xs font-semibold text-amber-600 hover:text-amber-700" type="button">i</button>
            </div>
            <button id="open-love-language-modal" class="px-3 py-1.5 rounded-lg border border-amber-300 text-amber-700 text-xs font-semibold bg-amber-50 hover:bg-amber-100" type="button">테스트하기</button>
          </div>
          <div id="care-mission-card" class="mt-3 relative rounded-xl border border-amber-200 bg-amber-50 min-h-[120px] p-4">
            <button id="open-care-mission-btn" type="button" class="hidden absolute top-3 right-3 px-2.5 py-1 rounded-full text-xs font-bold text-white shadow-sm" style="background: linear-gradient(135deg, #FFD700, #FFA500);">미션</button>
            <p id="care-mission-empty-text" class="absolute inset-0 m-0 text-xs text-gray-500 text-center flex items-center justify-center leading-relaxed">아직 미션이 없어요<br/>1주일에 2번 정도 미션이 날아올거에요.</p>
            <div id="care-mission-content" class="hidden">
              <p id="care-mission-title" class="text-sm font-bold text-gray-800 mb-1"></p>
              <p id="care-mission-body" class="text-sm text-gray-700 whitespace-pre-wrap"></p>
              <p id="care-mission-source" class="text-xs text-amber-700 mt-2"></p>
            </div>
          </div>
          <div id="care-mission-actions" class="hidden mt-3 grid grid-cols-1 gap-2">
            <button id="skip-care-mission-btn" type="button" class="w-full py-2.5 rounded-lg font-semibold border border-amber-300 text-amber-700 bg-amber-50 hover:bg-amber-100">건너뛰기 (+5 코인 환급)</button>
            <button id="complete-care-mission-btn" type="button" class="w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">미션 완료 체크하기 (+10 코인)</button>
          </div>
          <p id="care-mission-feedback" class="text-xs text-center mt-2 hidden"></p>
        </div>

        <div id="love-mission-info-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[73] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-bold text-amber-700">사랑의 언어 미션이란?</h3>
              <button type="button" id="close-love-mission-info-modal" class="p-2 rounded-full hover:bg-amber-50"><i class="fas fa-times text-gray-600"></i></button>
            </div>
            <div class="rounded-2xl border border-amber-200 bg-amber-50 p-4">
              <p class="text-sm text-gray-700 leading-relaxed mb-3">상대가 가장 사랑을 느끼는 방식으로, 상대를 위한 작은 행동 미션이에요.</p>
              <ul class="text-sm text-gray-700 space-y-2">
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>주 2회 정도, 상대의 사랑의 언어(1·2순위)에 맞춰 제공돼요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>상대는 내가 어떤 미션을 받았는지 알 수 없어요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>부담 없이 건너뛸 수 있어요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>미션을 열 때 코인 5개가 사용돼요 (건너뛰면 다시 돌아와요)</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>완료하면 코인 10개를 받아요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>완료 시, 상대에게 알림이 전송돼요</span></li>
              </ul>
            </div>
            <div class="mt-4 text-center text-xs text-amber-500">
              상대를 위한 작은 행동, 지금 실천해볼까요? 💛
            </div>
            <button id="confirm-love-mission-info-modal" type="button" class="mt-5 w-full py-3 rounded-xl font-bold text-white shadow-md hover:shadow-lg transition-all" style="background: linear-gradient(135deg, #FFD700, #FFA500);">확인했어요</button>
          </div>
        </div>

        <div id="settings-side-modal" class="hidden fixed inset-0 z-50">
          <div id="settings-side-backdrop" class="absolute inset-0 bg-black/40 opacity-0 transition-opacity duration-300"></div>
          <div id="settings-side-panel" class="absolute right-0 top-0 h-full w-[92%] max-w-md bg-[var(--app-bg)] shadow-2xl transform translate-x-full transition-transform duration-300 ease-out">
            <div class="h-full flex flex-col">
              <div class="relative flex items-center justify-end px-4 py-3 bg-[var(--app-bg)]">
                <h3 class="absolute left-1/2 -translate-x-1/2 text-2xl font-extrabold text-gray-900">설정</h3>
                <button id="close-settings-side-modal" type="button" class="w-9 h-9 rounded-full hover:bg-amber-50 text-gray-500">
                  <i class="fas fa-times"></i>
                </button>
              </div>
              <iframe id="settings-side-frame" title="settings" sandbox="allow-same-origin allow-scripts allow-forms allow-modals" class="flex-1 w-full border-0"></iframe>
            </div>
          </div>
        </div>

        <div id="saved-quotes-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 max-h-[80vh] overflow-hidden flex flex-col">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-bold text-amber-700">저장한 글귀</h3>
              <button id="close-saved-quotes-modal" type="button" class="p-2 hover:bg-amber-50 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-500"></i>
              </button>
            </div>
            <div id="saved-quotes-list" class="space-y-3 overflow-y-auto pr-1">
              <p class="text-sm text-gray-500">저장한 글귀가 없어요.</p>
            </div>
          </div>
        </div>

        <div id="jackpot-info-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-bold text-amber-700">사랑의 언어 미션이란?</h3>
              <button id="close-jackpot-info-modal" type="button" class="p-2 hover:bg-amber-50 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-500"></i>
              </button>
            </div>
            <div class="rounded-2xl border border-amber-200 bg-amber-50 p-4">
              <p class="text-sm text-gray-700 leading-relaxed mb-3">두 사람에게 도착하는 따뜻한 한 줄이에요.</p>
              <ul class="text-sm text-gray-700 space-y-2">
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>한 명이 열면, 두 사람 모두에게 전달돼요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>하루 한 번 받을 수 있어요</span></li>
                <li class="flex items-center gap-2"><span class="text-amber-500">•</span><span>코인 5개가 사용돼요</span></li>
              </ul>
            </div>
            <div class="mt-4 text-center text-xs text-amber-500">
              오늘도 따뜻한 한 줄, 함께 받아봐요 💛
            </div>
            <button id="confirm-jackpot-info-modal" type="button" class="mt-5 w-full py-3 rounded-xl font-bold text-white shadow-md hover:shadow-lg transition-all" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인했어요
            </button>
          </div>
        </div>

        <div id="love-language-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[70] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 w-full max-w-5xl h-[92vh] flex flex-col overflow-hidden">
            <div class="px-5 py-4 border-b border-amber-200 flex items-center justify-between">
              <h3 class="text-base font-bold text-amber-700">💌 사랑의 언어 테스트</h3>
              <button type="button" id="close-love-language-modal" class="p-2 rounded-full hover:bg-amber-50">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div id="love-language-result-panel" class="hidden px-5 py-3 border-b border-amber-100 bg-amber-50/60 grid grid-cols-2 gap-3">
              <div class="rounded-xl border border-amber-200 bg-white p-3">
                <p id="love-language-me-name" class="text-xs text-gray-500 mb-1">내 결과</p>
                <p id="love-language-me-top1" class="text-sm font-semibold text-gray-800">1순위: 미설정</p>
                <p id="love-language-me-top2" class="text-sm text-gray-700">2순위: 미설정</p>
              </div>
              <div class="rounded-xl border border-amber-200 bg-white p-3">
                <p id="love-language-partner-name" class="text-xs text-gray-500 mb-1">상대방 결과</p>
                <p id="love-language-partner-top1" class="text-sm font-semibold text-gray-800">1순위: 미설정</p>
                <p id="love-language-partner-top2" class="text-sm text-gray-700">2순위: 미설정</p>
              </div>
            </div>
            <div class="flex-1 grid grid-cols-1 md:grid-cols-2 gap-0 min-h-0">
              <div class="border-r border-amber-100 p-4 space-y-3 overflow-y-auto">
                <button id="save-love-language-btn" type="button" class="w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
                  결과 저장하기
                </button>
                <p id="love-language-feedback" class="text-xs text-center hidden"></p>
              </div>
              <div class="min-h-0 p-4 overflow-y-auto bg-amber-50/40">
                <div id="love-language-quiz-list" class="space-y-3"></div>
              </div>
            </div>
          </div>
        </div>

        <div id="partner-mission-complete-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[71] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-lg font-bold text-amber-700">💛 상대방 미션 완료</h3>
              <button type="button" id="close-partner-mission-complete-modal" class="p-2 rounded-full hover:bg-amber-50">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <p id="partner-mission-complete-text" class="text-sm text-gray-700 leading-relaxed"></p>
            <button id="confirm-partner-mission-complete-modal" type="button" class="mt-5 w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인했어요!
            </button>
          </div>
        </div>

        <div id="care-mission-complete-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[72] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 w-full max-w-sm p-5">
            <div class="flex items-center justify-between mb-2">
              <h3 class="text-base font-bold text-amber-700">💝 미션 완료 소식</h3>
              <button type="button" id="close-care-mission-complete-modal" class="p-2 rounded-full hover:bg-amber-50">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <p id="care-mission-complete-text" class="text-sm text-gray-700 leading-relaxed"></p>
            <button id="confirm-care-mission-complete-modal" type="button" class="mt-4 w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인했어요!
            </button>
          </div>
        </div>

        <div id="promise-note-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[62] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 w-full max-w-5xl h-[92vh] flex flex-col overflow-hidden">
            <div class="px-5 py-4 border-b border-gray-200 flex items-center justify-between">
              <h3 class="text-lg font-bold text-amber-700">우리 둘만의 약속 메모</h3>
              <button type="button" id="close-promise-note-modal" class="p-2 rounded-full hover:bg-amber-50">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div class="px-5 py-4 border-b border-gray-100 space-y-3">
              <input type="text" id="promise-note-title" placeholder="제목" class="w-full px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400" />
              <div class="flex items-center gap-2">
                <label for="promise-note-priority" class="text-sm text-gray-600 whitespace-nowrap">우선순위</label>
                <select id="promise-note-priority" class="flex-1 px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400">
                  <option value="5">★★★★★ (5)</option>
                  <option value="4">★★★★☆ (4)</option>
                  <option value="3" selected>★★★☆☆ (3)</option>
                  <option value="2">★★☆☆☆ (2)</option>
                  <option value="1">★☆☆☆☆ (1)</option>
                </select>
              </div>
              <textarea id="promise-note-content" rows="3" placeholder="내용" class="w-full px-3 py-2 border border-amber-200 rounded-lg focus:ring-2 focus:ring-amber-300 focus:border-amber-400 resize-none"></textarea>
              <button type="button" id="save-promise-note-btn" class="w-full py-2.5 rounded-lg font-bold text-white shadow-md" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
                저장하기
              </button>
              <p id="promise-note-feedback" class="text-xs text-center hidden"></p>
            </div>
            <div class="px-5 py-3 border-b border-gray-100 flex items-center justify-end gap-2">
              <label for="promise-note-sort" class="text-xs text-gray-500">정렬</label>
              <select id="promise-note-sort" class="px-2.5 py-1.5 border border-amber-200 rounded-md text-xs focus:ring-2 focus:ring-amber-300 focus:border-amber-400">
                <option value="latest" selected>최신순</option>
                <option value="priority">별점순</option>
              </select>
            </div>
            <div id="promise-note-list" class="px-5 py-4 overflow-y-auto space-y-3 min-h-[120px]">
              <p class="text-sm text-gray-500 text-center py-6">저장된 메모가 없어요.</p>
            </div>
          </div>
        </div>

        <div id="rewards-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full max-h-[85vh] flex flex-col overflow-hidden">
            <div class="px-6 pt-6 pb-4 border-b border-amber-200 flex items-center justify-between">
              <h3 class="text-xl font-bold flex items-center gap-2 text-amber-700">
                코인 누적 기록
              </h3>
              <button type="button" id="close-rewards-modal" class="p-2 rounded-full hover:bg-amber-50 transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div id="rewards-history" class="flex-1 overflow-y-auto px-6 py-4 space-y-3 min-h-[120px]">
              <p class="text-center py-8 text-base text-amber-700">아직 기록이 없어요 🐻</p>
            </div>
            <div class="px-6 pb-6 pt-2">
              <button type="button" id="how-to-earn-btn" class="w-full py-3.5 rounded-2xl font-semibold transition cursor-pointer border border-amber-300 bg-amber-50 text-amber-700 flex items-center justify-center gap-2 hover:bg-amber-100">
                <span>💡</span> 어떻게 모아요?
              </button>
            </div>
          </div>
        </div>

        <div id="rewards-guide-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[51] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6">
              <div class="text-center mb-6">
                <span class="text-5xl">💛</span>
                <h3 class="text-xl font-bold mt-2 text-amber-700">보상 안내</h3>
              </div>
              <div class="space-y-4 text-sm">
                <div class="rounded-2xl p-4 border-2" style="background: #FFFBEB; border-color: #FDE68A;">
                  <p class="font-bold mb-2" style="color: #B45309;">✨ 기본 보상</p>
                  <p class="text-gray-700">혼자 곰아워 → +1</p>
                  <p class="text-gray-700">둘이 함께 곰아워 → +4</p>
                </div>
                <div class="rounded-2xl p-4 border-2" style="background: #ECFDF5; border-color: #A7F3D0;">
                  <p class="font-bold mb-2" style="color: #047857;">🌱 개인 streak</p>
                  <p class="text-gray-700">3일 연속 → +10</p>
                  <p class="text-gray-700">7일 연속 → +20</p>
                  <p class="text-gray-700">14일 연속 → +40</p>
                  <p class="text-gray-700">30일 연속 → +80</p>
                </div>
                <div class="rounded-2xl p-4 border-2" style="background: #FDF2F8; border-color: #FBCFE8;">
                  <p class="font-bold mb-2" style="color: #BE185D;">💞 커플 streak</p>
                  <p class="text-gray-700">3일 함께 → +15</p>
                  <p class="text-gray-700">7일 함께 → +35</p>
                  <p class="text-gray-700">14일 함께 → +60</p>
                  <p class="text-gray-700">30일 함께 → +120</p>
                </div>
              </div>
              <button type="button" id="close-rewards-guide-modal" class="w-full mt-6 py-3.5 rounded-2xl font-bold text-white cursor-pointer shadow-lg" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
                확인
              </button>
            </div>
          </div>
        </div>
      </div>

      <nav class="fixed bottom-0 left-0 right-0 py-1.5 z-40 pointer-events-none" style="background: var(--tabbar-bg); padding-bottom: max(0.42rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-4 pointer-events-none">
          <div class="grid grid-cols-3 gap-0">
            <a href="/dashboard" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-calendar text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/history" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-book text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/settings" target="_self" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-user text-gray-900 text-lg"></i>
              </div>
            </a>
          </div>
        </div>
      </nav>

      <script dangerouslySetInnerHTML={{
        __html: `
          (function() {
            const leverBase = document.getElementById('jackpot-lever-base');
            const leverTrack = document.getElementById('jackpot-lever-track');
            const leverKnob = document.getElementById('jackpot-lever-knob');
            const saveBtn = document.getElementById('jackpot-save-btn');
            const statusEl = document.getElementById('jackpot-status');
            const quoteCard = document.getElementById('jackpot-quote-card');
            const emptySlot = document.getElementById('jackpot-empty-slot');
            const quoteText = document.getElementById('jackpot-quote-text');
            const quoteSource = document.getElementById('jackpot-quote-source');
            const quoteInline = document.getElementById('jackpot-quote-inline');
            const quoteInlineText = document.getElementById('jackpot-quote-inline-text');
            const quoteInlineSource = document.getElementById('jackpot-quote-inline-source');
            const drawMeta = document.getElementById('jackpot-draw-meta');
            const slotFrame = document.getElementById('jackpot-slot-frame');
            const reel = document.getElementById('jackpot-reel');
            const savedList = document.getElementById('saved-quotes-list');
            const openSavedQuotesBtn = document.getElementById('open-saved-quotes-btn');
            const savedQuotesModal = document.getElementById('saved-quotes-modal');
            const closeSavedQuotesModalBtn = document.getElementById('close-saved-quotes-modal');
            const infoBtn = document.getElementById('jackpot-info-btn');
            const infoModal = document.getElementById('jackpot-info-modal');
            const closeInfoModalBtn = document.getElementById('close-jackpot-info-modal');
            const confirmInfoModalBtn = document.getElementById('confirm-jackpot-info-modal');
            const openLoveLanguageModalBtn = document.getElementById('open-love-language-modal');
            const openLoveMissionInfoModalBtn = document.getElementById('open-love-mission-info-modal');
            const loveMissionInfoModal = document.getElementById('love-mission-info-modal');
            const closeLoveMissionInfoModalBtn = document.getElementById('close-love-mission-info-modal');
            const confirmLoveMissionInfoModalBtn = document.getElementById('confirm-love-mission-info-modal');
            const loveLanguageModal = document.getElementById('love-language-modal');
            const closeLoveLanguageModalBtn = document.getElementById('close-love-language-modal');
            const saveLoveLanguageBtn = document.getElementById('save-love-language-btn');
            const loveLanguageFeedback = document.getElementById('love-language-feedback');
            const loveLanguageQuizList = document.getElementById('love-language-quiz-list');
            const loveLanguageResultPanel = document.getElementById('love-language-result-panel');
            const loveLanguageMeName = document.getElementById('love-language-me-name');
            const loveLanguagePartnerName = document.getElementById('love-language-partner-name');
            const loveLanguageMeTop1 = document.getElementById('love-language-me-top1');
            const loveLanguageMeTop2 = document.getElementById('love-language-me-top2');
            const loveLanguagePartnerTop1 = document.getElementById('love-language-partner-top1');
            const loveLanguagePartnerTop2 = document.getElementById('love-language-partner-top2');
            const careMissionCardEl = document.getElementById('care-mission-card');
            const careMissionEmptyTextEl = document.getElementById('care-mission-empty-text');
            const careMissionContentEl = document.getElementById('care-mission-content');
            const careMissionActionsEl = document.getElementById('care-mission-actions');
            const careMissionTitleEl = document.getElementById('care-mission-title');
            const careMissionBodyEl = document.getElementById('care-mission-body');
            const careMissionSourceEl = document.getElementById('care-mission-source');
            const careMissionFeedbackEl = document.getElementById('care-mission-feedback');
            const openCareMissionBtn = document.getElementById('open-care-mission-btn');
            const skipCareMissionBtn = document.getElementById('skip-care-mission-btn');
            const completeCareMissionBtn = document.getElementById('complete-care-mission-btn');
            const careMissionCompleteModal = document.getElementById('care-mission-complete-modal');
            const careMissionCompleteText = document.getElementById('care-mission-complete-text');
            const closeCareMissionCompleteModalBtn = document.getElementById('close-care-mission-complete-modal');
            const confirmCareMissionCompleteModalBtn = document.getElementById('confirm-care-mission-complete-modal');
            const partnerMissionCompleteModal = document.getElementById('partner-mission-complete-modal');
            const partnerMissionCompleteText = document.getElementById('partner-mission-complete-text');
            const closePartnerMissionCompleteModalBtn = document.getElementById('close-partner-mission-complete-modal');
            const confirmPartnerMissionCompleteModalBtn = document.getElementById('confirm-partner-mission-complete-modal');
            const openSettingsSideModalBtn = document.getElementById('open-settings-side-modal');
            const settingsSideModal = document.getElementById('settings-side-modal');
            const settingsSideBackdrop = document.getElementById('settings-side-backdrop');
            const settingsSidePanel = document.getElementById('settings-side-panel');
            const closeSettingsSideModalBtn = document.getElementById('close-settings-side-modal');
            const settingsSideFrame = document.getElementById('settings-side-frame');
            let settingsFrameLoaded = false;
            let currentCareMission = null;
            let pendingCareMissionNoticeId = 0;
            let rewardsData = { totalCoins: 0, history: [] };
            let currentDraw = null;
            let canDrawToday = false;
            let isDrawing = false;
            let leverDragging = false;
            let leverStartY = 0;
            let leverOffset = 0;
            const LEVER_MAX_DROP = 46;
            const LEVER_TRIGGER_DROP = 16;
            const LEVER_LATCH_DROP = 36;

            const setLeverOffset = (next) => {
              leverOffset = Math.max(0, Math.min(LEVER_MAX_DROP, Number(next || 0)));
              if (leverKnob) leverKnob.style.transform = 'translateY(' + leverOffset + 'px)';
            };

            const releaseLever = (forceUp) => {
              if (!leverKnob) return;
              leverKnob.style.transition = 'transform 260ms cubic-bezier(0.22, 0.61, 0.36, 1)';
              const shouldStayDown = !forceUp && !!currentDraw;
              setLeverOffset(shouldStayDown ? LEVER_LATCH_DROP : 0);
              setTimeout(function() {
                if (leverKnob) leverKnob.style.transition = '';
              }, 280);
            };

            async function loadRewards() {
              try {
                const res = await fetch('/api/rewards/summary', { credentials: 'include' });
                const data = await res.json();
                if (data.success) {
                  rewardsData = { totalCoins: data.totalCoins || 0, history: data.history || [] };
                  const el = document.getElementById('coin-count');
                  if (el) el.textContent = String(rewardsData.totalCoins);
                }
              } catch (e) {
                console.error('보상 로드 실패:', e);
              }
            }

            (function() {
              const openBtn = document.getElementById('show-promise-note-btn');
              const modal = document.getElementById('promise-note-modal');
              const closeBtn = document.getElementById('close-promise-note-modal');
              const saveBtn = document.getElementById('save-promise-note-btn');
              const titleInput = document.getElementById('promise-note-title');
              const priorityInput = document.getElementById('promise-note-priority');
              const contentInput = document.getElementById('promise-note-content');
              const sortSelect = document.getElementById('promise-note-sort');
              const listEl = document.getElementById('promise-note-list');
              const feedbackEl = document.getElementById('promise-note-feedback');
              if (!openBtn || !modal || !saveBtn || !titleInput || !priorityInput || !contentInput || !sortSelect || !listEl || !feedbackEl) return;
              let noteCache = [];
              let editingNoteId = null;
              let deletingNoteId = null;

              const escapeHtml = (str) => String(str || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
              const resetNoteForm = () => {
                editingNoteId = null;
                titleInput.value = '';
                priorityInput.value = '3';
                contentInput.value = '';
              };

              const renderStars = (priority) => {
                const p = Math.max(1, Math.min(5, Number(priority || 3)));
                return '★'.repeat(p) + '☆'.repeat(5 - p);
              };

              function showFeedback(msg, isError) {
                feedbackEl.textContent = msg;
                feedbackEl.className = 'text-xs text-center ' + (isError ? 'text-red-600' : 'text-green-600');
                feedbackEl.classList.remove('hidden');
              }

              async function loadPromiseNotes() {
                try {
                  const sortBy = sortSelect.value === 'priority' ? 'priority' : 'latest';
                  const res = await fetch('/api/promise-notes?sort_by=' + encodeURIComponent(sortBy), { credentials: 'include' });
                  const data = await res.json();
                  if (!data.success) {
                    showFeedback(data.error || '메모를 불러오지 못했어요.', true);
                    return;
                  }
                  const notes = Array.isArray(data.notes) ? data.notes : [];
                  noteCache = notes;
                  if (notes.length === 0) {
                    listEl.innerHTML = '<p class="text-sm text-gray-500 text-center py-6">저장된 메모가 없어요.</p>';
                    return;
                  }
                  listEl.innerHTML = notes.map((note) => {
                    const noteId = String(note.id || '');
                    const title = escapeHtml(note.title || '');
                    const stars = renderStars(note.priority || 3);
                    const noteDate = escapeHtml((note.note_date || note.created_at || '').slice(0, 10));
                    const content = escapeHtml(note.content || '');
                    const author = escapeHtml(note.author_name || '우리');
                    return '<div class="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 relative">' +
                      '<div class="absolute top-2.5 right-2.5 flex items-center gap-1">' +
                        '<button type="button" class="promise-note-edit-btn w-7 h-7 rounded-full border border-amber-300 text-amber-700 hover:bg-amber-100 text-xs flex items-center justify-center" data-note-id="' + noteId + '" aria-label="메모 수정">' +
                          '<i class="fas fa-pen"></i>' +
                        '</button>' +
                        '<button type="button" class="promise-note-delete-btn w-7 h-7 rounded-full border border-red-300 text-red-600 hover:bg-red-50 text-xs flex items-center justify-center" data-note-id="' + noteId + '" aria-label="메모 삭제">' +
                          '<i class="fas fa-trash"></i>' +
                        '</button>' +
                      '</div>' +
                      '<p class="text-sm font-bold text-gray-800 pr-16 mb-1">' + title + '</p>' +
                      '<p class="text-xs text-amber-500 font-semibold mb-1">' + stars + '</p>' +
                      '<p class="text-xs text-gray-500 mb-2">작성: ' + author + '</p>' +
                      '<p class="text-sm text-gray-700 whitespace-pre-wrap">' + content + '</p>' +
                      '<p class="text-xs text-gray-500 mt-2">' + noteDate + '</p>' +
                    '</div>';
                  }).join('');
                } catch (_) {
                  showFeedback('메모를 불러오는 중 오류가 발생했어요.', true);
                }
              }

              function openModal() {
                modal.classList.remove('hidden');
                feedbackEl.classList.add('hidden');
                resetNoteForm();
                loadPromiseNotes();
              }

              function closeModal() {
                modal.classList.add('hidden');
              }

              openBtn.addEventListener('click', openModal);
              if (closeBtn) closeBtn.addEventListener('click', closeModal);
              modal.addEventListener('click', function(e) { if (e.target === modal) closeModal(); });
              listEl.addEventListener('click', async function(e) {
                const target = e.target;
                if (!(target instanceof HTMLElement)) return;
                const editBtn = target.closest('.promise-note-edit-btn');
                if (editBtn) {
                  const noteId = editBtn.getAttribute('data-note-id');
                  const note = noteCache.find((item) => String(item.id) === String(noteId));
                  if (!note) return;
                  editingNoteId = Number(note.id);
                  titleInput.value = String(note.title || '');
                  priorityInput.value = String(note.priority || 3);
                  contentInput.value = String(note.content || '');
                  feedbackEl.classList.add('hidden');
                  titleInput.focus();
                  return;
                }
                const deleteBtn = target.closest('.promise-note-delete-btn');
                if (!deleteBtn) return;
                const noteId = deleteBtn.getAttribute('data-note-id');
                if (!noteId || deletingNoteId === noteId) return;
                deletingNoteId = noteId;
                deleteBtn.setAttribute('disabled', 'true');
                try {
                  const res = await fetch('/api/promise-notes/' + noteId, {
                    method: 'DELETE',
                    credentials: 'include',
                  });
                  const data = await res.json();
                  if (!data.success) {
                    showFeedback(data.error || '삭제에 실패했어요.', true);
                    return;
                  }
                  if (editingNoteId === Number(noteId)) {
                    resetNoteForm();
                  }
                  showFeedback('약속 메모를 삭제했어요.', false);
                  await loadPromiseNotes();
                } catch (_) {
                  showFeedback('삭제 중 오류가 발생했어요.', true);
                } finally {
                  deletingNoteId = null;
                  deleteBtn.removeAttribute('disabled');
                }
              });

              saveBtn.addEventListener('click', async function() {
                const title = titleInput.value.trim();
                const priority = Number(priorityInput.value || 3);
                const content = contentInput.value.trim();
                if (!title || !content) {
                  showFeedback('제목과 내용을 모두 입력해주세요.', true);
                  return;
                }
                if (!Number.isInteger(priority) || priority < 1 || priority > 5) {
                  showFeedback('우선순위는 1~5 사이로 선택해주세요.', true);
                  return;
                }
                try {
                  const isEdit = Number.isInteger(editingNoteId) && editingNoteId > 0;
                  const endpoint = isEdit ? '/api/promise-notes/' + editingNoteId : '/api/promise-notes';
                  const method = isEdit ? 'PUT' : 'POST';
                  const res = await fetch(endpoint, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ title: title, priority: priority, content: content }),
                  });
                  const data = await res.json();
                  if (!data.success) {
                    showFeedback(data.error || '저장에 실패했어요.', true);
                    return;
                  }
                  showFeedback(isEdit ? '약속 메모를 수정했어요.' : '약속 메모를 저장했어요.', false);
                  resetNoteForm();
                  await loadPromiseNotes();
                } catch (_) {
                  showFeedback('저장 중 오류가 발생했어요.', true);
                }
              });
              sortSelect.addEventListener('change', function() { loadPromiseNotes(); });
            })();

            const getSubjectJosa = (name) => {
              const safeName = String(name || '').trim();
              if (!safeName) return '가';

              // 이름 뒤에 붙은 이모티콘/기호를 무시하고 마지막 한글 음절로 조사 판단
              let lastHangulCode = 0;
              for (let i = safeName.length - 1; i >= 0; i--) {
                const code = safeName.charCodeAt(i);
                if (code >= 0xac00 && code <= 0xd7a3) {
                  lastHangulCode = code;
                  break;
                }
              }
              if (!lastHangulCode) return '가';

              const hasJongseong = (lastHangulCode - 0xac00) % 28 !== 0;
              return hasJongseong ? '이' : '가';
            };

            const renderSavedQuotes = (savedQuotes) => {
              if (!savedQuotes || !savedQuotes.length) {
                savedList.innerHTML = '<p class="text-sm text-gray-500">저장한 글귀가 없어요.</p>';
                return;
              }
              savedList.innerHTML = savedQuotes.map((item) => {
                const saverName = String(item.saver_name || '우리');
                const saverJosa = getSubjectJosa(saverName);
                const saver = '<span class="text-amber-600 font-semibold">' + saverName + '</span>';
                const source = item.quote_source || '출처 미상';
                const savedId = Number(item.id || 0);
                const canUnsave = !!item.saved_by_me;
                const unsaveBtn = canUnsave
                  ? ('<button type="button" class="jackpot-unsave-btn absolute top-2 right-2 w-6 h-6 rounded-full text-gray-400 hover:text-gray-600 hover:bg-white/70 flex items-center justify-center" data-saved-id="' + String(savedId) + '" title="저장 취소">×</button>')
                  : '';
                return '<div class="relative rounded-2xl border border-amber-200 bg-amber-50 p-4">' +
                  unsaveBtn +
                  '<p class="text-sm text-gray-800 leading-relaxed whitespace-pre-wrap">' + (item.quote || '') + '</p>' +
                  '<p class="text-xs text-gray-500 mt-2">- ' + source + '</p>' +
                  '<p class="text-xs text-gray-500 mt-2">' + saver + saverJosa + ' 저장</p>' +
                '</div>';
              }).join('');
            };

            const updateSaveButtonState = (isSaved) => {
              if (!saveBtn) return;
              const saved = !!isSaved;
              saveBtn.className = saved
                ? 'absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-100 hover:bg-red-200 text-red-500 flex items-center justify-center shadow-sm'
                : 'absolute -top-1 -right-1 w-5 h-5 rounded-full bg-gray-100 hover:bg-gray-200 text-gray-400 flex items-center justify-center shadow-sm';
            };

            const renderTodayDraw = (draw) => {
              currentDraw = draw || null;
              if (!draw) {
                quoteCard.classList.add('hidden');
                if (emptySlot) emptySlot.classList.remove('hidden');
                quoteText.textContent = '';
                quoteSource.textContent = '';
                quoteText.classList.remove('hidden');
                quoteSource.classList.remove('hidden');
                quoteInline.classList.add('hidden');
                quoteInlineText.textContent = '';
                quoteInlineSource.textContent = '';
                drawMeta.textContent = '';
                updateSaveButtonState(false);
                releaseLever(true);
                return;
              }
              quoteCard.classList.remove('hidden');
              quoteCard.classList.add('jackpot-reveal');
              setTimeout(function() { quoteCard.classList.remove('jackpot-reveal'); }, 380);
              if (emptySlot) emptySlot.classList.add('hidden');
              quoteText.textContent = draw.quote ? ('"' + draw.quote + '"') : '';
              quoteSource.textContent = '- ' + (draw.quote_source || '저자 미상');
              quoteText.style.fontSize = '15px';
              quoteText.style.wordBreak = 'keep-all';
              quoteText.style.overflowWrap = 'break-word';
              quoteText.style.lineHeight = '1.45';
              quoteText.style.maxWidth = '100%';

              const lineHeightPx = parseFloat(window.getComputedStyle(quoteText).lineHeight || '21');
              const maxLines = 2;
              let guard = 0;
              while (guard < 6 && quoteText.scrollHeight > lineHeightPx * maxLines + 2) {
                const currentSize = parseFloat(window.getComputedStyle(quoteText).fontSize || '15');
                if (currentSize <= 13) break;
                quoteText.style.fontSize = (currentSize - 0.5) + 'px';
                guard += 1;
              }
              if (quoteText.scrollHeight > lineHeightPx * maxLines + 2) {
                const raw = String(draw.quote || '').trim();
                const mid = Math.floor(raw.length / 2);
                let splitIdx = -1;
                for (let i = 0; i < raw.length; i++) {
                  const idx = i % 2 === 0 ? mid + Math.floor(i / 2) : mid - Math.floor(i / 2) - 1;
                  if (idx > 5 && idx < raw.length - 5 && raw[idx] === ' ') {
                    splitIdx = idx;
                    break;
                  }
                }
                if (splitIdx > 0) {
                  const first = raw.slice(0, splitIdx).trim();
                  const second = raw.slice(splitIdx + 1).trim();
                  quoteText.textContent = '"' + first + '\\n' + second + '"';
                }
              }

              if (quoteText.scrollHeight > lineHeightPx * maxLines + 2) {
                quoteText.classList.add('hidden');
                quoteSource.classList.add('hidden');
                quoteInline.classList.remove('hidden');
                quoteInlineText.textContent = draw.quote ? ('"' + draw.quote + '"') : '';
                quoteInlineSource.textContent = ' - ' + (draw.quote_source || '저자 미상');
                quoteInline.style.fontSize = '13px';
                quoteInline.style.wordBreak = 'keep-all';
                quoteInline.style.overflowWrap = 'break-word';
                quoteInline.style.lineHeight = '1.4';
              } else {
                quoteText.classList.remove('hidden');
                quoteSource.classList.remove('hidden');
                quoteInline.classList.add('hidden');
                quoteInlineText.textContent = '';
                quoteInlineSource.textContent = '';
              }
              const drawerName = String(draw.drawer_name || '우리');
              drawMeta.textContent = ((draw.draw_date || '') + ' · ' + drawerName + getSubjectJosa(drawerName) + ' 당겼어요').trim();
              updateSaveButtonState(!!draw.saved_by_me || !!draw.saved_by_anyone);
              releaseLever(false);
            };

            const triggerDraw = async () => {
              if (isDrawing || !canDrawToday) return;
              isDrawing = true;
              try {
                statusEl.textContent = '슝~ 레버를 돌리는 중이에요...';
                if (slotFrame) {
                  slotFrame.classList.add('jackpot-shake');
                  setTimeout(function() { slotFrame.classList.remove('jackpot-shake'); }, 440);
                }
                if (reel) reel.classList.add('jackpot-spin');
                await new Promise(function(resolve) { setTimeout(resolve, 560); });
                const response = await fetch('/api/jackpot/draw', {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({})
                });
                const data = await response.json();
                if (!data.success) throw new Error(data.error || '레버 당기기에 실패했어요.');
                renderTodayDraw(data.draw || null);
                statusEl.textContent = data.already_drawn ? '오늘은 이미 레버를 당겼어요.' : '오늘의 글귀를 뽑았어요!';
              } catch (error) {
                console.error(error);
                statusEl.textContent = (error && error.message) ? error.message : '레버 당기기에 실패했어요.';
              } finally {
                if (reel) reel.classList.remove('jackpot-spin');
                isDrawing = false;
                await loadJackpotState();
              }
            };

            if (infoBtn && infoModal) {
              infoBtn.addEventListener('click', function() { infoModal.classList.remove('hidden'); });
              if (closeInfoModalBtn) closeInfoModalBtn.addEventListener('click', function() { infoModal.classList.add('hidden'); });
              if (confirmInfoModalBtn) confirmInfoModalBtn.addEventListener('click', function() { infoModal.classList.add('hidden'); });
              infoModal.addEventListener('click', function(e) {
                if (e.target === infoModal) infoModal.classList.add('hidden');
              });
            }

            const renderLoveLanguageState = (state) => {
              const me = state && state.me ? state.me : null;
              const partner = state && state.partner ? state.partner : null;
              if (loveLanguageResultPanel) {
                const hasResult = !!(me || partner);
                loveLanguageResultPanel.classList.toggle('hidden', !hasResult);
              }
              if (loveLanguageMeName) loveLanguageMeName.textContent = (me && me.name ? me.name : '내') + ' 결과';
              if (loveLanguagePartnerName) loveLanguagePartnerName.textContent = (partner && partner.name ? partner.name : '상대방') + ' 결과';
              if (loveLanguageMeTop1) loveLanguageMeTop1.textContent = '1순위: ' + (me && me.top1 ? me.top1 : '미설정');
              if (loveLanguageMeTop2) loveLanguageMeTop2.textContent = '2순위: ' + (me && me.top2 ? me.top2 : '미설정');
              if (loveLanguagePartnerTop1) loveLanguagePartnerTop1.textContent = '1순위: ' + (partner && partner.top1 ? partner.top1 : '미설정');
              if (loveLanguagePartnerTop2) loveLanguagePartnerTop2.textContent = '2순위: ' + (partner && partner.top2 ? partner.top2 : '미설정');
            };

            const LOVE_LANGUAGE_CODE_TO_NAME = {
              A: '인정의 말',
              B: '함께하는 시간',
              C: '선물',
              D: '봉사',
              E: '스킨십'
            };

            const LOVE_LANGUAGE_QUESTIONS = [
              { no: 1, a: { text: '상대방이 인정해 주는 말 듣는 것을 좋아한다', code: 'A' }, b: { text: '상대가 안아주는 것을 좋아한다', code: 'E' } },
              { no: 2, a: { text: '상대와 단둘이 보내는 시간을 좋아한다', code: 'B' }, b: { text: '상대가 실제적인 도움을 줄 때 사랑을 느낀다', code: 'D' } },
              { no: 3, a: { text: '상대에게 선물 받는 것을 좋아한다', code: 'C' }, b: { text: '상대와 함께 산책하는 시간을 좋아한다', code: 'B' } },
              { no: 4, a: { text: '상대가 나를 도와줄 때 사랑을 느낀다', code: 'D' }, b: { text: '상대에게 가벼운 신체 접촉을 받을 때 사랑을 느낀다', code: 'E' } },
              { no: 5, a: { text: '상대가 감싸 안아 줄 때 사랑을 느낀다', code: 'E' }, b: { text: '상대에게 선물을 받을 때 사랑을 느낀다', code: 'C' } },
              { no: 6, a: { text: '상대와 함께 외출하는 것을 좋아한다', code: 'B' }, b: { text: '상대와 손잡는 것을 좋아한다', code: 'E' } },
              { no: 7, a: { text: '상대가 나를 인정해 줄 때 사랑을 느낀다', code: 'A' }, b: { text: '눈에 보이는 선물이 의미가 있다', code: 'C' } },
              { no: 8, a: { text: '상대와 함께 붙어 앉는 것을 좋아한다', code: 'E' }, b: { text: '상대가 나에 대해 배려적이라고 할 때 좋아한다', code: 'A' } },
              { no: 9, a: { text: '상대와 함께 시간 보내는 것을 좋아한다', code: 'B' }, b: { text: '상대에게 작지만 선물 받는 것을 좋아한다', code: 'C' } },
              { no: 10, a: { text: '상대가 나를 도와줄 때 사랑을 느낀다', code: 'D' }, b: { text: '나를 이해해 주는 말들이 중요하다', code: 'A' } },
              { no: 11, a: { text: '상대와 함께 무언가 하는 것을 좋아한다', code: 'B' }, b: { text: '상대가 해주는 친절한 말들을 좋아한다', code: 'A' } },
              { no: 12, a: { text: '상대와 포옹할 때 완전함을 느낀다', code: 'E' }, b: { text: '상대의 말보다 행동을 볼 때 감동한다', code: 'D' } },
              { no: 13, a: { text: '상대의 칭찬을 좋아하고 비판은 회피하는 편이다', code: 'A' }, b: { text: '크진 않아도 자주 받는 선물이 좋다', code: 'C' } },
              { no: 14, a: { text: '상대가 자주 신체접촉을 해줄 때 더 친밀함을 느낀다', code: 'E' }, b: { text: '상대와 함께 뭔가 하거나 이야기할 때 친밀함을 느낀다', code: 'B' } },
              { no: 15, a: { text: '상대가 내가 한 일에 대해 칭찬해주는 것을 좋아한다', code: 'A' }, b: { text: '상대가 내 할 일을 도와주거나 해주면 사랑을 느낀다', code: 'D' } },
              { no: 16, a: { text: '상대와 잠에 들 때 손을 잡아주는 것을 좋아한다', code: 'E' }, b: { text: '상대가 내 이야기에 공감하며 들어주는 것을 좋아한다', code: 'B' } },
              { no: 17, a: { text: '상대에게 선물 받는 것을 즐거워한다', code: 'C' }, b: { text: '상대가 집안일을 도와줄 때 사랑을 느낀다', code: 'D' } },
              { no: 18, a: { text: '상대가 내 외모를 칭찬해 주는 것을 좋아한다', code: 'A' }, b: { text: '상대가 나를 이해하기 위해 시간을 내 줄 때 사랑을 느낀다', code: 'B' } },
              { no: 19, a: { text: '상대가 나를 어루만져 줄 때 편안함을 느낀다', code: 'E' }, b: { text: '나를 돕는 상대의 수고에 사랑을 느낀다', code: 'D' } },
              { no: 20, a: { text: '나를 위해 수고하는 상대에게 고마움을 느낀다', code: 'D' }, b: { text: '상대가 만든(준비한) 선물 받는 것을 좋아한다', code: 'C' } },
              { no: 21, a: { text: '상대가 나에게 집중할 때 큰 느낌을 받는다', code: 'B' }, b: { text: '상대가 나를 위해 실제로 힘쓸 때 느낌이 좋다', code: 'D' } },
              { no: 22, a: { text: '상대가 선물과 함께 내 생일을 축하할 때 사랑을 느낀다', code: 'C' }, b: { text: '내 생일에 직접 축하해 줄 때 사랑을 느낀다', code: 'A' } },
              { no: 23, a: { text: '상대가 집안일을 도와줄 때 사랑을 느낀다', code: 'D' }, b: { text: '상대가 선물을 줄 때 나를 생각해준 것이라 느낀다', code: 'C' } },
              { no: 24, a: { text: '상대가 선물과 함께 특별한 날을 기억해 줄 때 고마움을 느낀다', code: 'C' }, b: { text: '상대가 끝까지 내 얘기를 들어줄 때 고마움을 느낀다', code: 'B' } },
              { no: 25, a: { text: '상대와 장기간 여행을 즐긴다', code: 'B' }, b: { text: '상대가 나에게 관심을 주기 바란다', code: 'D' } },
              { no: 26, a: { text: '기대하지 않은 입맞춤이 나를 흥분시킨다', code: 'E' }, b: { text: '특별하지 않아도 선물을 받으면 기분이 좋다', code: 'C' } },
              { no: 27, a: { text: '상대에게 고맙다는 말을 듣는 것을 좋아한다', code: 'A' }, b: { text: '상대가 이야기하는 동안 나를 바라보는 것을 좋아한다', code: 'B' } },
              { no: 28, a: { text: '상대가 준 선물은 언제나 특별하다', code: 'C' }, b: { text: '상대가 가벼운 신체 접촉을 해 주는 것을 좋아한다', code: 'E' } },
              { no: 29, a: { text: '상대가 얼마나 고마워하는지 말할 때 사랑을 느낀다', code: 'A' }, b: { text: '상대가 내가 부탁한 일에 최선을 다해줄 때 사랑을 느낀다', code: 'D' } },
              { no: 30, a: { text: '매일 가벼운 신체 접촉을 원한다', code: 'E' }, b: { text: '매일 상대의 지지하는 말이 필요하다', code: 'A' } }
            ];

            const renderLoveLanguageQuiz = () => {
              if (!loveLanguageQuizList) return;
              loveLanguageQuizList.innerHTML = LOVE_LANGUAGE_QUESTIONS.map((q) => {
                const groupName = 'love-language-q-' + q.no;
                return '<div class="bg-white border border-amber-200 rounded-xl p-3">' +
                  '<p class="text-xs font-bold text-amber-700 mb-2">' + q.no + '번 문항</p>' +
                  '<label class="flex items-start gap-2 text-sm text-gray-700 cursor-pointer">' +
                    '<input type="radio" name="' + groupName + '" value="a" class="mt-1" />' +
                    '<span>' + q.a.text + '</span>' +
                  '</label>' +
                  '<label class="flex items-start gap-2 text-sm text-gray-700 cursor-pointer mt-2">' +
                    '<input type="radio" name="' + groupName + '" value="b" class="mt-1" />' +
                    '<span>' + q.b.text + '</span>' +
                  '</label>' +
                '</div>';
              }).join('');
            };

            const calculateLoveLanguageFromQuiz = () => {
              const scores = { A: 0, B: 0, C: 0, D: 0, E: 0 };
              for (const q of LOVE_LANGUAGE_QUESTIONS) {
                const selected = document.querySelector('input[name="love-language-q-' + q.no + '"]:checked');
                if (!selected) return { error: q.no + '번 문항을 선택해주세요.' };
                const code = selected.value === 'a' ? q.a.code : q.b.code;
                scores[code] += 1;
              }
              const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
              const top1 = LOVE_LANGUAGE_CODE_TO_NAME[ranked[0][0]];
              const top2 = LOVE_LANGUAGE_CODE_TO_NAME[ranked[1][0]];
              return { scores, top1, top2 };
            };

            const loadLoveLanguageState = async () => {
              try {
                const res = await fetch('/api/love-language/state', { credentials: 'same-origin' });
                const data = await res.json();
                if (!data || !data.success) return;
                renderLoveLanguageState(data);
              } catch (e) {
                console.error('love language state load failed', e);
              }
            };

            const renderCareMission = (data) => {
              const mission = data && data.mission ? data.mission : null;
              currentCareMission = mission;
              const hasMission = !!mission;
              const opened = !!(mission && mission.opened_by_me);
              const skipped = !!(mission && mission.skipped_by_me);
              const completed = !!(mission && mission.completed_by_me);
              const showMissionContent = hasMission && opened && !skipped;
              const showMissionBadge = hasMission && !!mission.available_now && !opened && !skipped && !completed;
              const showEmpty = !showMissionContent && !showMissionBadge;
              if (careMissionCardEl) careMissionCardEl.classList.toggle('bg-amber-50', true);
              if (careMissionEmptyTextEl) careMissionEmptyTextEl.classList.toggle('hidden', !showEmpty);
              if (careMissionContentEl) careMissionContentEl.classList.toggle('hidden', !showMissionContent);
              if (careMissionActionsEl) careMissionActionsEl.classList.toggle('hidden', !(showMissionContent && !completed));
              if (careMissionTitleEl) careMissionTitleEl.textContent = mission && mission.title ? mission.title : '';
              if (careMissionBodyEl) careMissionBodyEl.textContent = showMissionContent ? (mission.body || '') : '';
              if (careMissionSourceEl) {
                if (mission && showMissionContent && mission.based_on) {
                  careMissionSourceEl.textContent = '분석 기준: ' + mission.based_on;
                } else {
                  careMissionSourceEl.textContent = '';
                }
              }
              if (openCareMissionBtn) {
                const disabled = !showMissionBadge;
                openCareMissionBtn.disabled = disabled;
                openCareMissionBtn.classList.toggle('hidden', !showMissionBadge);
                openCareMissionBtn.textContent = '미션';
              }
              if (skipCareMissionBtn) {
                const disabled = !mission || !mission.opened_by_me || !!mission.skipped_by_me || !!mission.completed_by_me;
                skipCareMissionBtn.disabled = disabled;
              }
              if (completeCareMissionBtn) {
                const disabled = !mission || !mission.opened_by_me || !!mission.completed_by_me || !!mission.skipped_by_me;
                completeCareMissionBtn.disabled = disabled;
                completeCareMissionBtn.textContent = mission && mission.completed_by_me ? '이번 주 미션 완료됨' : '미션 완료 체크하기 (+10 코인)';
              }
              if (careMissionFeedbackEl && (!mission || skipped)) {
                careMissionFeedbackEl.classList.add('hidden');
              }
            };

            const loadCareMission = async () => {
              try {
                const res = await fetch('/api/care-mission/current', { credentials: 'same-origin' });
                const data = await res.json();
                if (!data || !data.success) return;
                renderCareMission(data);
                const notice = data.partner_notice;
                if (notice && notice.id && Number(notice.id) !== Number(pendingCareMissionNoticeId || 0)) {
                  pendingCareMissionNoticeId = Number(notice.id);
                  if (partnerMissionCompleteText) {
                    partnerMissionCompleteText.textContent = String(notice.actor_name || '상대방') + '님이 배려 미션을 완료했어요: ' + String(notice.mission_title || '');
                  }
                  if (partnerMissionCompleteModal) partnerMissionCompleteModal.classList.remove('hidden');
                }
              } catch (e) {
                console.error('care mission load failed', e);
              }
            };

            const closePartnerMissionModal = async () => {
              if (partnerMissionCompleteModal) partnerMissionCompleteModal.classList.add('hidden');
              if (!pendingCareMissionNoticeId) return;
              const target = pendingCareMissionNoticeId;
              pendingCareMissionNoticeId = 0;
              try {
                await fetch('/api/care-mission/notice-seen', {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ completion_id: target }),
                });
              } catch (_) {}
            };

            if (openCareMissionBtn && careMissionFeedbackEl) {
              openCareMissionBtn.addEventListener('click', async function() {
                if (!currentCareMission || !currentCareMission.mission_key) return;
                try {
                  openCareMissionBtn.setAttribute('disabled', 'true');
                  const res = await fetch('/api/care-mission/open', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mission_key: currentCareMission.mission_key }),
                  });
                  const data = await res.json();
                  if (!data || !data.success) throw new Error(data && data.error ? data.error : '미션 열기에 실패했어요.');
                  careMissionFeedbackEl.textContent = '미션을 열었어요! (-5 코인)';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-green-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                  await loadCareMission();
                  if (typeof loadRewards === 'function') await loadRewards();
                } catch (e) {
                  careMissionFeedbackEl.textContent = (e && e.message) ? e.message : '미션 열기 중 오류가 발생했어요.';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-red-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                } finally {
                  openCareMissionBtn.removeAttribute('disabled');
                }
              });
            }

            if (skipCareMissionBtn && careMissionFeedbackEl) {
              skipCareMissionBtn.addEventListener('click', async function() {
                if (!currentCareMission || !currentCareMission.mission_key) return;
                try {
                  skipCareMissionBtn.setAttribute('disabled', 'true');
                  const res = await fetch('/api/care-mission/skip', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mission_key: currentCareMission.mission_key }),
                  });
                  const data = await res.json();
                  if (!data || !data.success) throw new Error(data && data.error ? data.error : '건너뛰기에 실패했어요.');
                  careMissionFeedbackEl.textContent = '미션을 건너뛰었어요. (+5 코인 환급)';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-green-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                  await loadCareMission();
                  if (typeof loadRewards === 'function') await loadRewards();
                } catch (e) {
                  careMissionFeedbackEl.textContent = (e && e.message) ? e.message : '건너뛰기 중 오류가 발생했어요.';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-red-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                } finally {
                  skipCareMissionBtn.removeAttribute('disabled');
                }
              });
            }

            if (completeCareMissionBtn && careMissionFeedbackEl) {
              completeCareMissionBtn.addEventListener('click', async function() {
                if (!currentCareMission || !currentCareMission.mission_key) return;
                try {
                  completeCareMissionBtn.setAttribute('disabled', 'true');
                  const res = await fetch('/api/care-mission/complete', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mission_key: currentCareMission.mission_key }),
                  });
                  const data = await res.json();
                  if (!data || !data.success) throw new Error(data && data.error ? data.error : '미션 완료 처리에 실패했어요.');
                  careMissionFeedbackEl.textContent = '미션 완료! 상대방 마이페이지에 완료 소식이 전달됐어요.';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-green-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                  if (careMissionCompleteText) {
                    careMissionCompleteText.textContent = '완료 체크됐어요. 상대방에게도 미션 완료 소식이 전달됩니다.';
                  }
                  if (careMissionCompleteModal) careMissionCompleteModal.classList.remove('hidden');
                  await loadCareMission();
                  if (typeof loadRewards === 'function') await loadRewards();
                } catch (e) {
                  careMissionFeedbackEl.textContent = (e && e.message) ? e.message : '미션 완료 처리 중 오류가 발생했어요.';
                  careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-red-600';
                  careMissionFeedbackEl.classList.remove('hidden');
                } finally {
                  completeCareMissionBtn.removeAttribute('disabled');
                }
              });
            }

            if (closeCareMissionCompleteModalBtn && careMissionCompleteModal) {
              closeCareMissionCompleteModalBtn.addEventListener('click', function() {
                careMissionCompleteModal.classList.add('hidden');
              });
            }
            if (confirmCareMissionCompleteModalBtn && careMissionCompleteModal) {
              confirmCareMissionCompleteModalBtn.addEventListener('click', function() {
                careMissionCompleteModal.classList.add('hidden');
              });
            }
            if (careMissionCompleteModal) {
              careMissionCompleteModal.addEventListener('click', function(e) {
                if (e.target === careMissionCompleteModal) careMissionCompleteModal.classList.add('hidden');
              });
            }

            if (closePartnerMissionCompleteModalBtn) {
              closePartnerMissionCompleteModalBtn.addEventListener('click', closePartnerMissionModal);
            }
            if (confirmPartnerMissionCompleteModalBtn) {
              confirmPartnerMissionCompleteModalBtn.addEventListener('click', closePartnerMissionModal);
            }
            if (partnerMissionCompleteModal) {
              partnerMissionCompleteModal.addEventListener('click', function(e) {
                if (e.target === partnerMissionCompleteModal) closePartnerMissionModal();
              });
            }

            if (closePartnerMissionCompleteModalBtn) {
              closePartnerMissionCompleteModalBtn.addEventListener('click', function() { closePartnerMissionModal(); });
            }
            if (confirmPartnerMissionCompleteModalBtn) {
              confirmPartnerMissionCompleteModalBtn.addEventListener('click', function() { closePartnerMissionModal(); });
            }
            if (partnerMissionCompleteModal) {
              partnerMissionCompleteModal.addEventListener('click', function(e) {
                if (e.target === partnerMissionCompleteModal) closePartnerMissionModal();
              });
            }

            if (completeCareMissionBtn) {
              completeCareMissionBtn.addEventListener('click', async function() {
                if (!currentCareMission || !currentCareMission.mission_key) return;
                try {
                  completeCareMissionBtn.setAttribute('disabled', 'true');
                  const response = await fetch('/api/care-mission/complete', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mission_key: String(currentCareMission.mission_key) }),
                  });
                  const data = await response.json();
                  if (!data.success) throw new Error(data.error || '미션 완료 처리에 실패했어요.');
                  if (careMissionFeedbackEl) {
                    careMissionFeedbackEl.textContent = '완료 체크했어요! 상대방 마이페이지에 알림이 표시돼요.';
                    careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-green-600';
                    careMissionFeedbackEl.classList.remove('hidden');
                  }
                  await loadCareMission();
                } catch (e) {
                  if (careMissionFeedbackEl) {
                    careMissionFeedbackEl.textContent = (e && e.message) ? e.message : '완료 처리 중 오류가 발생했어요.';
                    careMissionFeedbackEl.className = 'text-xs text-center mt-2 text-red-600';
                    careMissionFeedbackEl.classList.remove('hidden');
                  }
                } finally {
                  completeCareMissionBtn.removeAttribute('disabled');
                }
              });
            }

            if (openLoveLanguageModalBtn && loveLanguageModal) {
              renderLoveLanguageQuiz();
              openLoveLanguageModalBtn.addEventListener('click', function() {
                loveLanguageModal.classList.remove('hidden');
                if (loveLanguageFeedback) loveLanguageFeedback.classList.add('hidden');
              });
              if (closeLoveLanguageModalBtn) {
                closeLoveLanguageModalBtn.addEventListener('click', function() {
                  loveLanguageModal.classList.add('hidden');
                });
              }
              loveLanguageModal.addEventListener('click', function(e) {
                if (e.target === loveLanguageModal) loveLanguageModal.classList.add('hidden');
              });
            }

            if (openLoveMissionInfoModalBtn && loveMissionInfoModal) {
              openLoveMissionInfoModalBtn.addEventListener('click', function() { loveMissionInfoModal.classList.remove('hidden'); });
              if (closeLoveMissionInfoModalBtn) closeLoveMissionInfoModalBtn.addEventListener('click', function() { loveMissionInfoModal.classList.add('hidden'); });
              if (confirmLoveMissionInfoModalBtn) confirmLoveMissionInfoModalBtn.addEventListener('click', function() { loveMissionInfoModal.classList.add('hidden'); });
              loveMissionInfoModal.addEventListener('click', function(e) {
                if (e.target === loveMissionInfoModal) loveMissionInfoModal.classList.add('hidden');
              });
            }

            if (saveLoveLanguageBtn && loveLanguageFeedback) {
              saveLoveLanguageBtn.addEventListener('click', async function() {
                const result = calculateLoveLanguageFromQuiz();
                if (result && result.error) {
                  loveLanguageFeedback.textContent = result.error;
                  loveLanguageFeedback.className = 'text-xs text-center text-red-600';
                  loveLanguageFeedback.classList.remove('hidden');
                  return;
                }
                try {
                  saveLoveLanguageBtn.setAttribute('disabled', 'true');
                  const res = await fetch('/api/love-language/save', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ top1: result.top1, top2: result.top2 })
                  });
                  const data = await res.json();
                  if (!data.success) throw new Error(data.error || '저장에 실패했어요.');
                  loveLanguageFeedback.textContent = '저장 완료! 결과를 반영했어요.';
                  loveLanguageFeedback.className = 'text-xs text-center text-green-600';
                  loveLanguageFeedback.classList.remove('hidden');
                  await loadLoveLanguageState();
                  await loadCareMission();
                  loveLanguageModal.classList.add('hidden');
                } catch (e) {
                  loveLanguageFeedback.textContent = (e && e.message) ? e.message : '저장 중 오류가 발생했어요.';
                  loveLanguageFeedback.className = 'text-xs text-center text-red-600';
                  loveLanguageFeedback.classList.remove('hidden');
                } finally {
                  saveLoveLanguageBtn.removeAttribute('disabled');
                }
              });
            }

            if (openSavedQuotesBtn && savedQuotesModal) {
              openSavedQuotesBtn.addEventListener('click', function() { savedQuotesModal.classList.remove('hidden'); });
              if (closeSavedQuotesModalBtn) closeSavedQuotesModalBtn.addEventListener('click', function() { savedQuotesModal.classList.add('hidden'); });
              savedQuotesModal.addEventListener('click', function(e) {
                if (e.target === savedQuotesModal) savedQuotesModal.classList.add('hidden');
              });
            }
            if (savedList) {
              savedList.addEventListener('click', async function(e) {
                const target = e.target;
                if (!(target instanceof HTMLElement)) return;
                const unsaveBtn = target.closest('.jackpot-unsave-btn');
                if (!unsaveBtn) return;
                const savedId = Number(unsaveBtn.getAttribute('data-saved-id') || 0);
                if (!savedId) return;
                unsaveBtn.setAttribute('disabled', 'true');
                try {
                  const response = await fetch('/api/jackpot/unsave', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ saved_id: savedId })
                  });
                  const data = await response.json();
                  if (!data.success) throw new Error(data.error || '저장 취소에 실패했어요.');
                  if (currentDraw && Number(currentDraw.id || 0) === Number(data.draw_id || 0)) {
                    currentDraw.saved_by_me = false;
                  }
                  await loadJackpotState();
                  statusEl.textContent = '저장을 취소했어요.';
                } catch (error) {
                  console.error(error);
                  alert((error && error.message) ? error.message : '저장 취소에 실패했어요.');
                } finally {
                  unsaveBtn.removeAttribute('disabled');
                }
              });
            }

            (function() {
              var coinBtn = document.getElementById('coin-btn');
              var closeBtn = document.getElementById('close-rewards-modal');
              var modal = document.getElementById('rewards-modal');
              var historyEl = document.getElementById('rewards-history');
              var howToBtn = document.getElementById('how-to-earn-btn');
              var guideModal = document.getElementById('rewards-guide-modal');
              var closeGuideBtn = document.getElementById('close-rewards-guide-modal');
              if (!coinBtn || !modal || !historyEl) return;
              coinBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (rewardsData.history.length === 0) {
                  historyEl.innerHTML = '<p class="text-center text-amber-600 py-8">아직 기록이 없어요 🐻</p>';
                } else {
                  historyEl.innerHTML = rewardsData.history.map(function(h) {
                    var bg = h.type === 'streak_individual'
                      ? 'bg-green-50 border-green-200'
                      : (h.type === 'streak_couple'
                        ? 'bg-pink-50 border-pink-200'
                        : ((h.type === 'jackpot_quote' || h.type === 'care_mission')
                          ? 'bg-orange-50 border-orange-200'
                          : 'bg-amber-50 border-amber-100'));
                    var icon = h.type === 'streak_individual' ? '🌱' : (h.type === 'streak_couple' ? '💞' : (h.type === 'jackpot_quote' ? '🕊️' : (h.type === 'care_mission' ? '💌' : '✨')));
                    var rawLabel = String(h.label || '');
                    var label = h.type === 'jackpot_quote' ? rawLabel : rawLabel.replace(/^[✨🌱💞🕊️🎰💌]+\\s*/, '');
                    label = label.replace(/\\s[+-]\\d+(?:코인)?\\s*$/u, '').trim();
                    var amount = Number(h.coins || h.amount || 0);
                    var amountText = (amount >= 0 ? '+' : '') + amount;
                    var date = String(h.reward_date || h.created_at || '').slice(0, 10);
                    return '<div class=\"rounded-xl border px-4 py-3 ' + bg + '\">' +
                      '<div class=\"text-sm font-semibold text-gray-800\">' + icon + ' ' + label + '</div>' +
                      '<div class=\"text-xs text-gray-500 mt-1\">' + date + '</div>' +
                      '<div class=\"text-sm font-bold text-amber-700 mt-1\">' + amountText + ' 코인</div>' +
                    '</div>';
                  }).join('');
                }
                modal.classList.remove('hidden');
              });
              if (closeBtn) closeBtn.addEventListener('click', function() { modal.classList.add('hidden'); });
              modal.addEventListener('click', function(e) { if (e.target === modal) modal.classList.add('hidden'); });
              if (howToBtn && guideModal) howToBtn.addEventListener('click', function() { guideModal.classList.remove('hidden'); });
              if (closeGuideBtn && guideModal) closeGuideBtn.addEventListener('click', function() { guideModal.classList.add('hidden'); });
              if (guideModal) guideModal.addEventListener('click', function(e) { if (e.target === guideModal) guideModal.classList.add('hidden'); });
            })();

            if (openSettingsSideModalBtn && settingsSideModal && settingsSideBackdrop && settingsSidePanel) {
              const installFrameGuards = function() {
                if (!settingsSideFrame || !settingsSideFrame.contentWindow) return;
                try {
                  const frameWindow = settingsSideFrame.contentWindow;
                  const frameDoc = frameWindow.document;
                  if (!frameDoc || frameWindow.__gomawoModalGuardInstalled) return;
                  frameWindow.__gomawoModalGuardInstalled = true;

                  const normalize = function(url) {
                    try { return new URL(url, frameWindow.location.href).toString(); } catch (_) { return ''; }
                  };

                  frameWindow.open = function(url) {
                    const next = normalize(url);
                    if (next) frameWindow.location.href = next;
                    return null;
                  };

                  frameDoc.querySelectorAll('a[target="_blank"]').forEach(function(a) {
                    a.setAttribute('target', '_self');
                  });

                  frameDoc.addEventListener('click', function(e) {
                    const anchor = e.target && e.target.closest ? e.target.closest('a[target="_blank"]') : null;
                    if (!anchor) return;
                    const href = anchor.getAttribute('href');
                    if (!href || href.indexOf('javascript:') === 0) return;
                    e.preventDefault();
                    e.stopPropagation();
                    const next = normalize(href);
                    if (next) frameWindow.location.href = next;
                  }, true);
                } catch (error) {
                  console.error('settings frame guard install failed', error);
                }
              };

              if (settingsSideFrame) {
                settingsSideFrame.addEventListener('load', function() {
                  installFrameGuards();
                });
              }

              const openSettingsModal = async function() {
                if (settingsSideFrame && !settingsFrameLoaded) {
                  try {
                    const response = await fetch('/account-settings?embedded=1&from=settings-modal', { credentials: 'same-origin' });
                    const html = await response.text();
                    settingsSideFrame.setAttribute('srcdoc', html);
                    settingsFrameLoaded = true;
                  } catch (error) {
                    console.error('settings frame load failed', error);
                  }
                }
                settingsSideModal.classList.remove('hidden');
                requestAnimationFrame(function() {
                  settingsSideBackdrop.classList.remove('opacity-0');
                  settingsSidePanel.classList.remove('translate-x-full');
                });
              };
              const closeSettingsModal = function() {
                settingsSideBackdrop.classList.add('opacity-0');
                settingsSidePanel.classList.add('translate-x-full');
                setTimeout(function() {
                  settingsSideModal.classList.add('hidden');
                }, 300);
              };
              openSettingsSideModalBtn.addEventListener('click', function() { openSettingsModal(); });
              settingsSideBackdrop.addEventListener('click', closeSettingsModal);
              if (closeSettingsSideModalBtn) {
                closeSettingsSideModalBtn.addEventListener('click', closeSettingsModal);
              }
            }

            const loadJackpotState = async () => {
              try {
                const response = await fetch('/api/jackpot/state', { credentials: 'same-origin' });
                const data = await response.json();
                if (!data.success) throw new Error(data.error || '상태 조회에 실패했어요.');

                renderTodayDraw(data.today_draw);
                renderSavedQuotes(data.saved_quotes || []);

                canDrawToday = !!data.can_draw;
                if (data.can_draw) {
                  if (leverTrack) leverTrack.classList.remove('opacity-50');
                  statusEl.textContent = '레버를 당겨 랜덤 글귀를 받아보세요.';
                } else {
                  if (leverTrack) leverTrack.classList.add('opacity-50');
                  statusEl.textContent = data.reason || '오늘은 이미 레버를 당겼어요.';
                }
              } catch (error) {
                console.error(error);
                statusEl.textContent = '잭팟 정보를 불러오지 못했어요.';
              }
            };

            if (leverTrack && leverKnob) {
              const startLeverDrag = function(clientY) {
                if (!canDrawToday || isDrawing) return;
                leverDragging = true;
                leverStartY = clientY - leverOffset;
                leverKnob.style.transition = 'none';
              };
              const moveLever = function(clientY) {
                if (!leverDragging) return;
                const rawDelta = clientY - leverStartY;
                const easedDelta = rawDelta <= 0 ? 0 : rawDelta * 1.1;
                setLeverOffset(easedDelta);
              };
              const endLeverDrag = function() {
                if (!leverDragging) return;
                leverDragging = false;
                const shouldTrigger = leverOffset >= LEVER_TRIGGER_DROP;
                if (shouldTrigger) {
                  if (leverKnob) {
                    leverKnob.style.transition = 'transform 220ms cubic-bezier(0.22, 0.61, 0.36, 1)';
                    setLeverOffset(LEVER_LATCH_DROP);
                    setTimeout(function() {
                      if (leverKnob) leverKnob.style.transition = '';
                    }, 240);
                  }
                  leverKnob.classList.add('jackpot-lever-pop');
                  setTimeout(function() { leverKnob.classList.remove('jackpot-lever-pop'); }, 260);
                  triggerDraw();
                } else {
                  releaseLever(true);
                }
              };

              const onLeverPointerDown = function(e) {
                e.preventDefault();
                if (leverKnob && typeof leverKnob.setPointerCapture === 'function') {
                  leverKnob.setPointerCapture(e.pointerId);
                }
                startLeverDrag(e.clientY);
              };
              leverKnob.addEventListener('pointerdown', onLeverPointerDown);
              if (leverTrack) leverTrack.addEventListener('pointerdown', onLeverPointerDown);
              if (leverBase) leverBase.addEventListener('pointerdown', onLeverPointerDown);
              leverKnob.addEventListener('pointermove', function(e) { moveLever(e.clientY); });
              leverKnob.addEventListener('pointerup', function() { endLeverDrag(); });
              leverKnob.addEventListener('pointercancel', function() { endLeverDrag(); });
              window.addEventListener('pointermove', function(e) { moveLever(e.clientY); });
              window.addEventListener('pointerup', function() { endLeverDrag(); });
            }

            saveBtn.addEventListener('click', async () => {
              if (!currentDraw || !currentDraw.id) {
                alert('먼저 글귀를 뽑아주세요.');
                return;
              }
              try {
                saveBtn.disabled = true;
                const response = await fetch('/api/jackpot/save', {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ draw_id: currentDraw.id })
                });
                const data = await response.json();
                if (!data.success) throw new Error(data.error || '저장에 실패했어요.');
                statusEl.textContent = '저장되었어요';
                if (currentDraw) {
                  currentDraw.saved_by_me = true;
                  updateSaveButtonState(true);
                }
                await loadJackpotState();
              } catch (error) {
                console.error(error);
                alert((error && error.message) ? error.message : '저장에 실패했어요.');
              } finally {
                saveBtn.disabled = false;
              }
            });

            loadJackpotState();
            loadRewards();
            loadLoveLanguageState();
            loadCareMission();
          })();
        `
      }} />
    </div>,
    { title: '마이페이지 - 곰아워' }
  )
})

// 계정 설정 페이지 (기존 마이페이지)
app.get('/account-settings', async (c) => {
  const isEmbedded = c.req.query('embedded') === '1'
  const fromModal = c.req.query('from') === 'settings-modal'
  if (!isEmbedded || !fromModal) {
    return c.redirect('/settings')
  }

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
  const hasPin = !!(dbUser?.pin as string | null)
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
    <div class={`min-h-screen ${isEmbedded ? 'pb-6' : 'pb-32'}`} style="background: var(--app-bg);">
      <div class={`max-w-md mx-auto px-4 ${isEmbedded ? 'py-2' : 'py-6'}`}>
        {/* 헤더 */}
        {!isEmbedded && (
        <div class="flex items-center justify-between mb-6">
            <h1 class="text-2xl font-bold text-gray-800">설정</h1>
        </div>
        )}

        {/* 프로필 - 닉네임만 표시 */}
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-6 text-center">
          <p class="text-xl font-bold text-gray-800" id="user-name-display">{userName}</p>
          <button type="button" id="edit-name-btn" class="settings-menu-item inline-flex items-center justify-center gap-2 py-3 px-6 mt-2 text-base text-gray-500 hover:text-amber-600 transition rounded-xl cursor-pointer">
            <i class="fas fa-pencil-alt"></i>닉네임 수정
          </button>
        </div>

        {/* 닉네임 수정 모달 */}
        <div id="edit-name-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xl font-bold text-amber-700">닉네임 수정</h3>
              <button type="button" id="close-name-modal" class="p-2 hover:bg-amber-50 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <input 
              type="text" 
              id="new-name-input"
              value={userName}
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400 mb-4"
              placeholder="새 닉네임"
            />
            <button type="button" id="save-name-btn" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
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

          <a id="met-date-btn" href="#" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">💕</span>
              <span class="text-base font-semibold text-gray-800">우리가 만난 날 설정하기</span>
            </div>
            <div class="flex items-center gap-2">
              {metDate ? <span class="text-sm text-amber-600">{metDate}</span> : null}
            <i class="fas fa-chevron-right text-gray-400"></i>
            </div>
          </a>

          <a href="#" onclick="document.getElementById('feedback-modal').classList.remove('hidden');return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">💡</span>
              <span class="text-base font-semibold text-gray-800">제안/문의하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>

          <a href="#" onclick="window.__openPinSettings();return false" class="settings-menu-item w-full flex items-center justify-between p-5 hover:bg-gray-50 transition border-b border-gray-100 cursor-pointer no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">🔒</span>
              <span id="pin-settings-label" class="text-base font-semibold text-gray-800">비밀번호 설정하기</span>
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
          <a href="/logout" class="w-full flex items-center justify-between p-5 hover:bg-gray-50 transition no-underline text-inherit">
            <div class="flex items-center">
              <span class="text-2xl mr-3">👋</span>
              <span class="text-base font-semibold text-gray-800">로그아웃하기</span>
            </div>
            <i class="fas fa-chevron-right text-gray-400"></i>
          </a>
        </div>

        {/* 계정 삭제 확인 모달 */}
        <div id="delete-account-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
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

        {/* 커플 미연동 안내 모달 */}
        <div id="partner-required-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[55] flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6 text-center">
            <p class="text-lg text-gray-800 mb-6">커플 연동 후 설정할 수 있어요</p>
            <button type="button" onclick="document.getElementById('partner-required-modal').classList.add('hidden')" class="w-full py-3 rounded-xl font-bold text-white text-base cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              확인
            </button>
          </div>
        </div>

        {/* 우리가 만난 날 설정 모달 */}
        <div id="met-date-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-bold text-gray-800">우리가 만난 날 설정하기</h3>
              <button type="button" onclick="document.getElementById('met-date-modal').classList.add('hidden')" class="p-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
                <i class="fas fa-times text-gray-600"></i>
              </button>
            </div>
            <div class="relative mb-4 date-time-input-wrap">
              <div class="form-input-box w-full px-4 py-3 border-2 border-amber-200 rounded-2xl bg-white text-gray-800" id="met-date-display">{metDate ? `${metDate.split('-')[0]}. ${parseInt(metDate.split('-')[1],10)}. ${parseInt(metDate.split('-')[2],10)}.` : '날짜 선택'}</div>
              <input type="date" id="new-met-date" value={metDate} class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            </div>
            <button type="button" onclick="window.__saveMetDate()" class="w-full py-3.5 rounded-xl font-bold text-white text-base shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-check mr-2"></i>저장
            </button>
          </div>
        </div>

        {/* 상대방 연동 모달 */}
        <div id="partner-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
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
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-2xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400 mb-4 text-center text-lg font-mono"
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
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
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
            <button id="pin-clear-btn" type="button" class="hidden relative z-10 mt-4 w-full py-3 rounded-xl font-semibold text-red-600 border border-red-300 hover:bg-red-50 cursor-pointer">
              비밀번호 해지하기
            </button>
            <p id="pin-error" class="text-center text-sm text-red-500 mt-3 hidden">비밀번호가 일치하지 않습니다.</p>
          </div>
        </div>

        {/* 제안/문의 모달 */}
        <div id="feedback-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-3xl shadow-2xl border-4 border-amber-400 max-w-md w-full p-6">
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
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400 mb-3"
              placeholder="제목"
            />
            <textarea 
              id="feedback-message"
              rows="5"
              class="w-full px-4 py-3 border-2 border-amber-200 rounded-xl focus:ring-2 focus:ring-amber-300 focus:border-amber-400 mb-4 resize-none"
              placeholder="내용을 입력해주세요"
            ></textarea>
            <button type="button" id="send-feedback-btn" onclick="window.__sendFeedback()" class="w-full py-3 rounded-xl font-bold text-white text-lg shadow-lg hover:shadow-xl transition-all cursor-pointer" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
              <i class="fas fa-paper-plane mr-2"></i>전송하기
            </button>
          </div>
        </div>
      </div>

      {!isEmbedded && (
        <nav class="fixed bottom-0 left-0 right-0 py-1.5 z-40 pointer-events-none" style="background: var(--tabbar-bg); padding-bottom: max(0.42rem, env(safe-area-inset-bottom));">
          <div class="max-w-md mx-auto px-4 pointer-events-none">
            <div class="grid grid-cols-3 gap-0">
              <a href="/dashboard" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
                <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                  <i class="fas fa-calendar text-gray-400 text-lg"></i>
              </div>
            </a>
              <a href="/history" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
                <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                  <i class="fas fa-book text-gray-400 text-lg"></i>
              </div>
            </a>
              <a href="/settings" target="_self" class="pointer-events-auto flex flex-col items-center justify-center py-1 min-h-[40px]">
                <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                  <i class="fas fa-cog text-gray-900 text-lg"></i>
              </div>
            </a>
          </div>
        </div>
        </nav>
      )}

      <script dangerouslySetInnerHTML={{
        __html: `
          const currentUser = { name: ${JSON.stringify(userName)}, email: ${JSON.stringify(user.email || user.id || '') }};
          const currentGender = ${JSON.stringify(userGender)};
          const currentNotificationTime = ${JSON.stringify(notificationTime)};
          const currentCoupleCode = ${JSON.stringify(coupleCode)};
          const isPartnerLinked = ${JSON.stringify(isPartnerLinked)};
          let pinEnabled = ${JSON.stringify(hasPin)};
          
          window.__openMetDate = function() {
            fetch('/api/user/partner-status', { credentials: 'include' }).then(function(r) { return r.json(); }).then(function(data) {
              if (!data.linked) document.getElementById('partner-required-modal').classList.remove('hidden');
              else document.getElementById('met-date-modal').classList.remove('hidden');
            }).catch(function() { document.getElementById('partner-required-modal').classList.remove('hidden'); });
          };
          
          (function(){ var b = document.getElementById('met-date-btn'); if(b) b.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); if(typeof window.__openMetDate==='function') window.__openMetDate(); }); })();

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
              if (data.success) { window.location.href = '/dashboard?show_promise=1&from_link=1'; }
              else alert(data.error || '연동에 실패했습니다.');
            } catch (e) { alert('연동 중 오류가 발생했습니다.'); }
          };
          
          // 닉네임 수정 (null 체크 + 터치 최적화)
          (function(){
            var editBtn = document.getElementById('edit-name-btn');
            var closeBtn = document.getElementById('close-name-modal');
            var saveBtn = document.getElementById('save-name-btn');
            var modal = document.getElementById('edit-name-modal');
            if (editBtn && modal) editBtn.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); modal.classList.remove('hidden'); });
            if (closeBtn && modal) closeBtn.addEventListener('click', function(e){ e.preventDefault(); modal.classList.add('hidden'); });
            if (saveBtn) saveBtn.addEventListener('click', async function(e) {
              e.preventDefault();
              e.stopPropagation();
              var newName = (document.getElementById('new-name-input') || {}).value;
              if (newName) newName = newName.trim();
            if (!newName) {
              alert('닉네임을 입력해주세요!');
              return;
            }

            try {
              var res = await fetch('/api/user/update-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ name: newName })
              });
              var data = await res.json();
              if (data.success) {
                var displayEl = document.getElementById('user-name-display');
                var inputEl = document.getElementById('new-name-input');
                if (displayEl) displayEl.textContent = newName;
                if (inputEl) inputEl.value = newName;
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
          })();

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
                  document.getElementById('copy-main-code-btn').classList.remove('hidden');
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

          // 메인 코드 복사 (DOM에서 현재 코드 읽기)
          const copyMainCodeBtn = document.getElementById('copy-main-code-btn');
          if (copyMainCodeBtn) {
            copyMainCodeBtn.addEventListener('click', () => {
              const code = document.getElementById('main-couple-code').textContent || '';
              if (!code || code === '------') return;
              navigator.clipboard.writeText(code);
              alert('커플 코드가 복사되었어요! 💕');
            });
          }

          const pinDots = document.querySelectorAll('#pin-dots span');
          const pinStepText = document.getElementById('pin-step-text');
          const pinSettingsLabel = document.getElementById('pin-settings-label');
          const pinClearBtn = document.getElementById('pin-clear-btn');
          let pinStep = 1;
          let firstPin = '';
          let pinValue = '';

          function refreshPinMenu() {
            if (!pinSettingsLabel) return;
            pinSettingsLabel.textContent = '비밀번호 설정하기';
            if (pinClearBtn) {
              pinClearBtn.classList.toggle('hidden', !pinEnabled);
            }
          }

          refreshPinMenu();

          window.__openPinSettings = function() {
            document.getElementById('password-modal').classList.remove('hidden');
            if (typeof resetPin === 'function') resetPin();
            refreshPinMenu();
          };

          function clearPinAction() {
            if (!pinEnabled) return;
            if (pinClearBtn) pinClearBtn.setAttribute('disabled', 'true');
            fetch('/api/user/clear-password', {
              method: 'POST',
              credentials: 'include',
            })
              .then(function(r) { return r.json(); })
              .then(function(data) {
                if (!data.success) {
                  alert(data.error || '비밀번호 해지에 실패했습니다.');
              return;
            }
                pinEnabled = false;
                refreshPinMenu();
                sessionStorage.setItem('pin_unlocked', '1');
                document.getElementById('password-modal').classList.add('hidden');
                alert('비밀번호가 해지되었습니다.');
              })
              .catch(function() {
                alert('비밀번호 해지 중 오류가 발생했습니다.');
              })
              .finally(function() {
                if (pinClearBtn) pinClearBtn.removeAttribute('disabled');
              });
          }

          window.__clearPin = clearPinAction;
          if (pinClearBtn) {
            pinClearBtn.addEventListener('click', function(e) {
              e.preventDefault();
              e.stopPropagation();
              clearPinAction();
            });
          }

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
                    if (data.success) {
                      document.getElementById('password-modal').classList.add('hidden');
                      pinEnabled = true;
                      refreshPinMenu();
                      sessionStorage.setItem('pin_unlocked', '1');
                      alert('비밀번호가 설정되었습니다! 🔒');
                    }
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

// 콜라주 갤러리 페이지 (핀터레스트 스타일)
app.get('/collage', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }
  // 닉네임/성별/알림시간 미설정 시에도 콜라주는 접근 가능 (설정 강제 리다이렉트 제거)

  return c.render(
    <div class="min-h-screen pb-24" style="background: var(--app-bg);">
      <div class="max-w-md mx-auto px-4 py-4">
        {/* 헤더 - 우리의 곰아워 보드 + 추가 버튼 */}
        <div class="flex items-center justify-center mb-6 relative">
          <h1 class="text-xl font-bold text-gray-800 text-center">우리의 곰아워 보드</h1>
          <a href="/collage/create" class="absolute right-0 w-10 h-10 rounded-full flex items-center justify-center shadow-md hover:shadow-lg transition" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            <i class="fas fa-plus text-white text-lg"></i>
          </a>
        </div>

        {/* 저장된 보드 그리드 - 3x3 */}
        <div id="collage-gallery" class="grid grid-cols-3 gap-2 sm:gap-3">
          {/* JavaScript로 동적 생성 */}
        </div>

        {/* 빈 상태 */}
        <div id="collage-empty" class="hidden text-center py-16">
          <div class="text-6xl mb-4">🖼️</div>
          <p class="text-gray-600 font-medium text-center">아직 만든 보드가 없어요</p>
          <p class="text-sm text-gray-500 mt-2 text-center">추가 버튼을 눌러 첫 보드를 만들어보세요!</p>
          <a href="/collage/create" class="inline-block mt-6 py-3 px-8 rounded-2xl font-bold text-white text-center" style="background: linear-gradient(135deg, #FFD700, #FFA500);">
            <i class="fas fa-plus mr-2"></i>보드 만들기
          </a>
        </div>
      </div>

      <script dangerouslySetInnerHTML={{
        __html: `
          (function() {
            var key = 'gom_hour_collages';
            var list = [];
            try { list = JSON.parse(localStorage.getItem(key) || '[]'); } catch(e) {}
            var gallery = document.getElementById('collage-gallery');
            var empty = document.getElementById('collage-empty');
            if (list.length === 0) {
              gallery.classList.add('hidden');
              empty.classList.remove('hidden');
            } else {
              empty.classList.add('hidden');
              gallery.innerHTML = list.map(function(item) {
                var label = (item.title && item.title.trim()) ? item.title.trim() : ((function(){ var d = new Date(item.createdAt || 0); return (d.getMonth()+1) + '/' + d.getDate(); })());
                var editUrl = '/collage/create?edit=' + encodeURIComponent(item.id);
                return '<div class="block relative rounded-xl overflow-hidden shadow-md bg-white aspect-square group" style="position:relative"><a href="' + editUrl + '" class="block absolute inset-0 z-0"><img src="' + item.dataUrl + '" alt="보드" class="w-full h-full object-cover" /></a><a href="' + editUrl + '" class="absolute top-1 right-1 z-10 w-7 h-7 rounded-full bg-white/90 flex items-center justify-center shadow" title="편집"><i class="fas fa-pen text-amber-600 text-xs"></i></a><div class="absolute bottom-0 left-0 right-0 z-10 px-1.5 py-1 flex items-center justify-between" style="background: rgba(0,0,0,0.5);"><span class="text-white text-[10px] sm:text-xs truncate flex-1 min-w-0">' + label + '</span><div class="flex items-center gap-0.5" style="flex-shrink:0"><a href="' + item.dataUrl + '" download="collage-' + item.id + '.png" class="text-white p-1.5 rounded-full hover:bg-white/30" title="다운로드" onclick="event.stopPropagation()"><i class="fas fa-download text-[10px]"></i></a><button type="button" class="collage-delete-btn text-white p-1.5 rounded-full hover:bg-white/30" data-id="' + item.id + '" title="삭제" onclick="event.stopPropagation()"><i class="fas fa-trash-alt text-[10px]"></i></button></div></div></div>';
              }).join('');
              gallery.querySelectorAll('.collage-delete-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                  e.preventDefault();
                  e.stopPropagation();
                  if (confirm('이 보드를 삭제할까요?')) {
                    var id = btn.getAttribute('data-id');
                    list = list.filter(function(x) { return x.id !== id; });
                    localStorage.setItem(key, JSON.stringify(list));
                    location.reload();
                  }
                });
              });
            }
          })();
        `
      }} />

      {/* 하단 네비게이션 - 보드 */}
      <nav class="fixed bottom-0 left-0 right-0 py-1.5 z-50" style="background: var(--tabbar-bg); padding-bottom: max(0.42rem, env(safe-area-inset-bottom));">
        <div class="max-w-md mx-auto px-4">
          <div class="grid grid-cols-3 gap-0">
            <a href="/dashboard" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-calendar text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/history" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-book text-gray-400 text-lg"></i>
              </div>
            </a>
            <a href="/settings" target="_self" class="flex flex-col items-center justify-center py-1 min-h-[40px]">
              <div class="w-11 h-11 rounded-full bg-transparent flex items-center justify-center">
                <i class="fas fa-user text-gray-400 text-lg"></i>
              </div>
            </a>
          </div>
        </div>
      </nav>
    </div>,
    { title: '우리의 곰아워 보드 - 곰아워' }
  )
})

// 콜라주 도구탭 iframe (클릭 보장용 - Fabric 캔버스와 분리)
app.get('/collage/toolbar-iframe', (c) => {
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:#fff;padding:8px 12px;padding-bottom:max(0.5rem,env(safe-area-inset-bottom))}
    .toolbar-row{display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:wrap}
    .tab{flex:1;min-width:44px;display:flex;align-items:center;justify-content:center;padding:10px 8px;border:2px solid transparent;background:transparent;cursor:pointer;border-radius:10px;font-size:18px;color:#4b5563}
    .tab.active{border-color:#fbbf24;color:#b45309}
    .tab-undo,.tab-redo{padding:8px 12px;background:#f3f4f6;border:none;border-radius:10px;cursor:pointer;font-size:16px;color:#4b5563;flex-shrink:0}
    .tab-undo,.tab-redo{cursor:pointer}
    .view-main{display:flex}
    .view-main.hide{display:none}
    .view-draw{display:none;align-items:center;justify-content:center;gap:8px}
    .view-draw.show{display:flex}
    .draw-tool{width:48px;height:48px;border:2px solid #e5e7eb;border-radius:12px;background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:18px;color:#374151}
    .draw-tool.active{border-color:#fbbf24;color:#b45309}
    .btn-back{padding:8px 12px;background:#f3f4f6;border:none;border-radius:10px;cursor:pointer;font-size:16px;color:#4b5563}
  </style></head><body>
    <div id="view-main" class="view-main toolbar-row">
      <button class="tab" data-tab="draw"><i class="fas fa-pen-fancy"></i></button>
      <button class="tab" data-tab="text"><i class="fas fa-font"></i></button>
      <button class="tab" data-tab="photo"><i class="fas fa-image"></i></button>
      <button class="tab" data-tab="eraser"><i class="fas fa-eraser"></i></button>
    </div>
    <div id="view-draw" class="view-draw">
      <input type="color" id="draw-color-picker" value="#000000" style="width:44px;height:44px;padding:0;border:2px solid #e5e7eb;border-radius:12px;cursor:pointer;background:transparent" title="색상" />
      <button class="btn-back" title="돌아가기"><i class="fas fa-arrow-left"></i></button>
    </div>
    <input type="file" id="photo-input" accept="image/*" multiple style="display:none" />
    <script>
      (function(){
        var parent=window.parent;
        var viewMain=document.getElementById('view-main');
        var viewDraw=document.getElementById('view-draw');
        function showMain(){viewMain.classList.remove('hide');viewDraw.classList.remove('show')}
        function showDraw(){viewMain.classList.add('hide');viewDraw.classList.add('show')}
        viewMain.querySelectorAll('.tab[data-tab]').forEach(function(btn){
          btn.onclick=function(){
            var t=btn.getAttribute('data-tab');
            if(t==='draw'){ showDraw(); viewMain.querySelectorAll('.tab').forEach(function(b){b.classList.remove('active');b.style.borderColor='transparent'}); var col=document.getElementById('draw-color-picker'); parent.postMessage({type:'collageTab',tab:'draw'},'*'); parent.postMessage({type:'collageSetBrush',brush:'pen',color:col?col.value:'#000000'},'*'); return; }
            viewMain.querySelectorAll('.tab').forEach(function(b){b.classList.remove('active');b.style.borderColor='transparent'});
            btn.classList.add('active');btn.style.borderColor='#fbbf24';
            parent.postMessage({type:'collageTab',tab:t},'*');
            if(t==='photo'){ document.getElementById('photo-input').value=''; document.getElementById('photo-input').click(); }
            if(t==='text'){ parent.postMessage({type:'collageAddText'},'*'); }
          };
        });
        var currentBrush='pen';
        var colorPicker=document.getElementById('draw-color-picker');
        if(colorPicker){
          colorPicker.onchange=function(){
            parent.postMessage({type:'collageSetBrush',brush:currentBrush,color:this.value},'*');
          };
        }
        viewDraw.querySelector('.btn-back').onclick=function(){ showMain(); viewMain.querySelectorAll('.tab').forEach(function(b){b.classList.remove('active');b.style.borderColor='transparent'}); parent.postMessage({type:'collageTab',tab:'idle'},'*'); };
        document.getElementById('photo-input').onchange=function(e){
          var files=e.target.files||[];
          for(var i=0;i<files.length;i++){
            var r=new FileReader();
            r.onload=(function(f){return function(ev){parent.postMessage({type:'collageAddPhotoData',dataUrl:ev.target.result},'*');};})(files[i]);
            r.readAsDataURL(files[i]);
          }
          e.target.value='';
        };
      })();
    </script>
  </body></html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
})

// 콜라주 만들기/편집 페이지
app.get('/collage/create', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) {
    return c.redirect('/app/login')
  }
  // 닉네임/성별/알림시간 미설정 시에도 콜라주 만들기 접근 가능

  return c.render(
    <div class="h-screen flex flex-col" style="background: #E5E7EB; touch-action: manipulation;">
      {/* 헤더 - 고정 */}
      <div id="collage-header" class="bg-white shadow-sm px-4 py-3 flex items-center justify-between flex-shrink-0" style="z-index: 1000; pointer-events: auto;">
        <a href="/collage" class="p-2 -ml-2 hover:bg-gray-100 rounded-full transition cursor-pointer">
          <i class="fas fa-arrow-left text-gray-600 text-xl"></i>
        </a>
        <h2 class="text-lg font-bold text-gray-800 text-center flex-1">보드 만들기</h2>
        <div class="flex items-center gap-2">
          <button type="button" id="collage-undo-btn" title="뒤로가기" class="p-2 rounded-lg bg-gray-100 text-gray-600" style="min-width: 44px; min-height: 44px; cursor: pointer;"><i class="fas fa-undo"></i></button>
          <button type="button" id="collage-redo-btn" title="앞으로가기" class="p-2 rounded-lg bg-gray-100 text-gray-600" style="min-width: 44px; min-height: 44px; cursor: pointer;"><i class="fas fa-redo"></i></button>
          <button type="button" id="collage-save-btn" data-collage="save" class="px-4 py-2 rounded-xl font-semibold text-sm text-white" style="background: linear-gradient(135deg,#FFD700,#FFA500); min-width: 72px; min-height: 44px; cursor: pointer; pointer-events: auto;">저장하기</button>
        </div>
      </div>

      {/* 스크롤 가능 영역: 도구 + 캔버스 */}
      <div class="flex-1 overflow-y-auto overflow-x-hidden" style="min-height: 0;">
      {/* 도구 탭바 - 캔버스 위에 배치 (캔버스가 덮지 않도록) */}
      <div id="collage-toolbar" class="bg-white border-b border-gray-100 px-4 py-3 flex justify-center items-center flex-shrink-0" style="position:relative;z-index:100;pointer-events:auto;">
        <div id="view-main" class="flex items-center justify-center gap-2 flex-wrap" style="max-width: 420px;">
          <a href="javascript:void(0)" data-tool="draw" onclick="(window.__collageClick||{}).draw&&window.__collageClick.draw();return false" class="flex-1 min-w-[44px] p-2.5 border-2 border-transparent rounded-lg text-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-pen-fancy"></i></a>
          <a href="javascript:void(0)" data-tool="text" onclick="(window.__collageClick||{}).text&&window.__collageClick.text();return false" class="flex-1 min-w-[44px] p-2.5 border-2 border-transparent rounded-lg text-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-font"></i></a>
          <a href="javascript:void(0)" data-tool="photo" onclick="(window.__collageClick||{}).photo&&window.__collageClick.photo();return false" class="flex-1 min-w-[44px] p-2.5 border-2 border-transparent rounded-lg text-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-image"></i></a>
          <input type="color" id="collage-bg-color" value="#FF8C00" title="배경색" style="width:44px;height:44px;padding:2px;border:2px solid #e5e7eb;border-radius:12px;cursor:pointer;background:transparent;flex-shrink:0" />
          <a href="javascript:void(0)" data-tool="eraser" onclick="(window.__collageClick||{}).eraser&&window.__collageClick.eraser();return false" class="flex-1 min-w-[44px] p-2.5 border-2 border-transparent rounded-lg text-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-eraser"></i></a>
        </div>
        <div id="view-text" class="flex items-center justify-center gap-2 flex-wrap" style="max-width: 420px; display: none;">
          <input type="color" id="collage-text-color" value="#000000" title="텍스트 색상" style="width:44px;height:44px;padding:2px;border:2px solid #e5e7eb;border-radius:12px;cursor:pointer;background:transparent;flex-shrink:0" />
          <div class="flex items-center gap-2 px-2">
            <span class="text-xs text-gray-500">크기</span>
            <input type="range" id="text-size-slider" min="12" max="72" value="24" title="텍스트 크기" class="w-20 h-2" style="accent-color:#fbbf24" />
          </div>
          <a href="javascript:void(0)" data-tool="back" onclick="(window.__collageClick||{}).textBack&&window.__collageClick.textBack();return false" class="px-3 py-2 bg-gray-100 rounded-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-arrow-left"></i></a>
        </div>
        <div id="view-draw" class="flex items-center justify-center gap-2 flex-wrap" style="max-width: 420px; display: none;">
          <a href="javascript:void(0)" data-brush="pen" onclick="(window.__collageClick||{}).brush&&window.__collageClick.brush('pen')();return false" class="w-12 h-12 border-2 border-gray-200 rounded-xl flex items-center justify-center text-lg text-gray-600" style="cursor:pointer;text-decoration:none;color:inherit" title="펜"><i class="fas fa-pen"></i></a>
          <a href="javascript:void(0)" data-brush="marker" onclick="(window.__collageClick||{}).brush&&window.__collageClick.brush('marker')();return false" class="w-12 h-12 border-2 border-gray-200 rounded-xl flex items-center justify-center text-lg text-gray-600" style="cursor:pointer;text-decoration:none;color:inherit" title="마커"><i class="fas fa-marker"></i></a>
          <a href="javascript:void(0)" data-brush="highlighter" onclick="(window.__collageClick||{}).brush&&window.__collageClick.brush('highlighter')();return false" class="w-12 h-12 border-2 border-gray-200 rounded-xl flex items-center justify-center text-lg text-gray-600" style="cursor:pointer;text-decoration:none;color:inherit" title="하이라이터"><i class="fas fa-highlighter"></i></a>
          <input type="color" id="draw-color-picker" value="#000000" style="width:44px;height:44px;padding:0;border:2px solid #e5e7eb;border-radius:12px;cursor:pointer;background:transparent" title="색상" />
          <a href="javascript:void(0)" data-tool="back" onclick="(window.__collageClick||{}).back&&window.__collageClick.back();return false" class="px-3 py-2 bg-gray-100 rounded-lg text-gray-600 flex items-center justify-center" style="cursor:pointer;text-decoration:none;color:inherit"><i class="fas fa-arrow-left"></i></a>
        </div>
      </div>

      {/* 캔버스 영역 - 도구 탭 아래, 스크롤 가능 */}
      <div class="p-4 pb-8 relative" style="z-index: 1;">
        <div class="bg-white rounded-2xl shadow-xl overflow-visible mx-auto flex flex-col items-center" style="max-width: 360px;">
          <div id="canvas-wrapper" class="collage-canvas-box relative bg-orange-100 overflow-hidden flex justify-center items-center" style="width: 100%; max-width: 360px; aspect-ratio: 3/4; min-height: 280px; pointer-events: auto;">
            <canvas id="collage-canvas" style="display: block;"></canvas>
          </div>
        </div>
      </div>
      </div>
      <input type="file" id="collage-file-input" accept="image/*" multiple class="hidden" />

      {/* 저장 모달 - 앱 스타일 */}
      <div id="collage-save-modal" class="fixed inset-0 z-[2000] flex items-center justify-center p-4" style="display: none; background: rgba(0,0,0,0.4);">
        <div class="w-full max-w-sm rounded-2xl shadow-2xl overflow-hidden" style="background: linear-gradient(to bottom, #FFFBF0, #FFF5E1); border: 1px solid rgba(255,215,0,0.3);">
          <div class="px-6 py-5">
            <h3 class="text-lg font-bold text-gray-800 text-center mb-1">보드 저장</h3>
            <p class="text-sm text-gray-500 text-center mb-4">보드 이름을 입력해주세요</p>
            <input type="text" id="collage-save-name-input" placeholder="예: 우리의 첫 보드" maxLength="20" class="w-full px-4 py-3 rounded-xl border-2 border-amber-200 bg-white text-gray-800 placeholder-gray-400 focus:border-amber-400 focus:outline-none focus:ring-2 focus:ring-amber-200/50" />
          </div>
          <div class="flex border-t border-amber-100">
            <button type="button" id="collage-save-modal-cancel" class="flex-1 py-3.5 text-gray-600 font-medium hover:bg-amber-50/50 transition">취소</button>
            <button type="button" id="collage-save-modal-confirm" class="flex-1 py-3.5 font-semibold text-amber-700 hover:bg-amber-100/50 transition" style="background: linear-gradient(135deg, rgba(255,215,0,0.3), rgba(255,165,0,0.2));">저장</button>
          </div>
        </div>
      </div>

      <style dangerouslySetInnerHTML={{
        __html: `
          .collage-canvas-box { overflow: hidden !important; position: relative !important; touch-action: pan-y manipulation; }
          .collage-canvas-box.canvas-active { touch-action: none !important; -webkit-user-select: none; user-select: none; }
          .collage-canvas-box .canvas-container { position: relative !important; pointer-events: auto !important; touch-action: pan-y manipulation !important; }
          .collage-canvas-box.canvas-active .canvas-container { touch-action: none !important; }
          .collage-canvas-box .upper-canvas, .collage-canvas-box .lower-canvas { position: relative !important; pointer-events: auto !important; touch-action: inherit !important; }
          #collage-toolbar button, #collage-toolbar input, #collage-toolbar a, #collage-header button, #collage-header a { min-height: 44px; min-width: 44px; -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
          #collage-save-modal button { min-height: 44px; -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
          #collage-toolbar button i, #collage-header button i { pointer-events: none; }
          .fabric-text-editing { font-weight: 600 !important; text-shadow: 0 0 2px rgba(255,255,255,0.9), 0 1px 2px rgba(0,0,0,0.3) !important; }
        `
      }} />
      <script dangerouslySetInnerHTML={{ __html: 'window.__collageClick=window.__collageClick||{};' }} />
      <script src="https://unpkg.com/fabric@5.3.0/dist/fabric.min.js"></script>
      <script dangerouslySetInnerHTML={{
        __html: `
          window.__collageClick = {};
          (function() {
            function init() {
            try {
            if (typeof fabric === 'undefined') {
              var s = document.createElement('script');
              s.src = 'https://unpkg.com/fabric@5.3.0/dist/fabric.min.js';
              s.onload = function() { setTimeout(init, 50); };
              document.head.appendChild(s);
              return;
            }
            var canvasEl = document.getElementById('collage-canvas');
            if (!canvasEl) return;
            var w = Math.min((window.innerWidth || 360) - 32, 360);
            w = Math.max(w, 280);
            var h = Math.round(w * 4 / 3);
            canvasEl.width = w;
            canvasEl.height = h;
            var size = w;

            var canvas = new fabric.Canvas('collage-canvas', { selection: false, freeDrawingCursor: 'crosshair', allowTouchScrolling: false });
            canvas.selection = false;
            canvas.isDrawingMode = false;
            canvas.freeDrawingCursor = 'crosshair';
            canvas.selectionColor = 'rgba(255,255,255,0.3)';
            canvas.selectionBorderColor = '#ffffff';
            fabric.Object.prototype.set({ borderColor: '#ffffff', cornerColor: '#ffffff' });
            canvas.setWidth(w);
            canvas.setHeight(h);
            canvas.backgroundColor = '#FF8C00';
            var wrapperEl = canvas.wrapperEl || (canvas.upperCanvasEl && canvas.upperCanvasEl.parentElement);
            var canvasWrapper = document.getElementById('canvas-wrapper');
            if (wrapperEl) {
              wrapperEl.style.width = w + 'px';
              wrapperEl.style.height = h + 'px';
              wrapperEl.style.maxWidth = '100%';
              wrapperEl.style.position = 'relative';
              if (canvasWrapper && wrapperEl.parentElement !== canvasWrapper) {
                canvasWrapper.appendChild(wrapperEl);
              }
            }

            var eraserMode = false;
            var drawingMode = false;
            var currentDrawColor = '#000000';
            var brushWidth = 2;
            var brushColor = '#000000';
            var isCustomDrawing = false;
            var customDrawPath = null;
            function getDrawColor() {
              var inp = document.getElementById('draw-color-picker');
              return inp ? inp.value : '#000000';
            }
            function hexToRgba(hex, alpha) {
              var str = String(hex || '').trim().replace(/^#/, '');
              var rgb = str.match(/^([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i) || str.match(/^([a-f\d])([a-f\d])([a-f\d])$/i);
              if (rgb) {
                var r = (rgb[1].length === 1 ? parseInt(rgb[1]+rgb[1],16) : parseInt(rgb[1],16));
                var g = (rgb[2].length === 1 ? parseInt(rgb[2]+rgb[2],16) : parseInt(rgb[2],16));
                var b = (rgb[3].length === 1 ? parseInt(rgb[3]+rgb[3],16) : parseInt(rgb[3],16));
                return 'rgba(' + r + ',' + g + ',' + b + ',' + (alpha != null ? alpha : 1) + ')';
              }
              var m = str.match(/rgba?\\(\\s*(\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([\\d.]+))?\\s*\\)/i);
              if (m) return 'rgba(' + m[1] + ',' + m[2] + ',' + m[3] + ',' + (m[4] != null ? m[4] : (alpha != null ? alpha : 1)) + ')';
              return null;
            }
            function getPointerFromEvent(e) {
              var ev = (e.touches && e.touches[0]) || (e.changedTouches && e.changedTouches[0]) || e;
              if (!ev || (ev.clientX == null && ev.clientY == null)) return null;
              return canvas.getPointer ? canvas.getPointer(ev) : (function() {
                var el = canvas.upperCanvasEl || canvas.getElement();
                if (!el) return null;
                var r = el.getBoundingClientRect();
                var scaleX = (canvas.width || w) / r.width;
                var scaleY = (canvas.height || h) / r.height;
                return { x: (ev.clientX - r.left) * scaleX, y: (ev.clientY - r.top) * scaleY };
              })();
            }
            function isTouchOnCanvas(e) {
              var ev = (e.touches && e.touches[0]) || e;
              if (!ev || ev.clientX == null) return true;
              var wr = canvasWrapper && canvasWrapper.getBoundingClientRect();
              if (!wr) return true;
              return ev.clientX >= wr.left && ev.clientX <= wr.right && ev.clientY >= wr.top && ev.clientY <= wr.bottom;
            }
            function customDrawPointerDown(e) {
              if (!drawingMode || eraserMode) return;
              if (e.touches && !isTouchOnCanvas(e)) return;
              e.preventDefault();
              e.stopPropagation();
              isCustomDrawing = true;
              var p = getPointerFromEvent(e);
              if (p) {
                customDrawPath = new fabric.Path('M ' + p.x + ' ' + p.y, {
                  stroke: brushColor,
                  strokeWidth: brushWidth,
                  strokeLineCap: 'round',
                  strokeLineJoin: 'round',
                  fill: '',
                  selectable: false,
                  evented: false
                });
                canvas.add(customDrawPath);
                if (bgRect) canvas.sendToBack(bgRect);
              }
            }
            function customDrawPointerMove(e) {
              if (!isCustomDrawing || !customDrawPath) return;
              e.preventDefault();
              var p = getPointerFromEvent(e);
              if (p && customDrawPath.path) {
                customDrawPath.path.push(['L', p.x, p.y]);
                canvas.requestRenderAll();
              }
            }
            function customDrawPointerUp(e) {
              if (!isCustomDrawing) return;
              e.preventDefault();
              isCustomDrawing = false;
              if (customDrawPath) {
                customDrawPath.set({ selectable: true, evented: true, hasControls: true, lockScalingX: false, lockScalingY: false });
                saveHistory();
                customDrawPath = null;
              }
              canvas.requestRenderAll();
            }
            function attachCustomDrawListeners() {
              var el = canvasWrapper || canvas.upperCanvasEl || canvas.wrapperEl;
              if (!el) return;
              var opts = { passive: false, capture: true };
              el.addEventListener('mousedown', customDrawPointerDown, opts);
              el.addEventListener('mousemove', customDrawPointerMove, opts);
              el.addEventListener('mouseup', customDrawPointerUp, opts);
              el.addEventListener('mouseleave', customDrawPointerUp, opts);
              el.addEventListener('touchstart', customDrawPointerDown, opts);
              document.body.addEventListener('touchmove', customDrawPointerMove, opts);
              document.body.addEventListener('touchend', customDrawPointerUp, opts);
              document.body.addEventListener('touchcancel', customDrawPointerUp, opts);
            }
            function detachCustomDrawListeners() {
              var el = canvas.upperCanvasEl || canvas.wrapperEl || canvasWrapper;
              if (!el) return;
              var opts = { capture: true };
              el.removeEventListener('mousedown', customDrawPointerDown, opts);
              el.removeEventListener('mousemove', customDrawPointerMove, opts);
              el.removeEventListener('mouseup', customDrawPointerUp, opts);
              el.removeEventListener('mouseleave', customDrawPointerUp, opts);
              el.removeEventListener('touchstart', customDrawPointerDown, opts);
              document.body.removeEventListener('touchmove', customDrawPointerMove, opts);
              document.body.removeEventListener('touchend', customDrawPointerUp, opts);
              document.body.removeEventListener('touchcancel', customDrawPointerUp, opts);
            }
            function setBrush(type, color) {
              var c = color || getDrawColor();
              currentDrawColor = c;
              if (type === 'eraser') {
                eraserMode = true;
                canvas.isDrawingMode = false;
                drawingMode = false;
                detachCustomDrawListeners();
              } else {
                eraserMode = false;
                drawingMode = true;
                canvas.isDrawingMode = false;
                detachCustomDrawListeners();
                if (type === 'pen') { brushWidth = 4; brushColor = c; }
                else if (type === 'marker') { brushWidth = 10; brushColor = c; }
                else if (type === 'highlighter') { brushWidth = 14; brushColor = hexToRgba(c, 0.5) || 'rgba(255,255,0,0.5)'; }
                else { brushWidth = 4; brushColor = c; }
                attachCustomDrawListeners();
              }
            }

            var canvasBox = document.getElementById('canvas-wrapper');
            function setCanvasActive(active) {
              if (canvasBox) canvasBox.classList.toggle('canvas-active', !!active);
              canvas.allowTouchScrolling = !active;
            }
            function applyTab(tab) {
              if (tab === 'idle') {
                eraserMode = false;
                drawingMode = false;
                canvas.isDrawingMode = false;
                detachCustomDrawListeners();
                canvas.selection = true;
                setCanvasActive(false);
                canvas.discardActiveObject();
                canvas.requestRenderAll();
              } else if (tab === 'eraser') {
                eraserMode = true;
                drawingMode = false;
                canvas.isDrawingMode = false;
                detachCustomDrawListeners();
                canvas.selection = true;
                setCanvasActive(true);
                canvas.discardActiveObject();
                canvas.requestRenderAll();
              } else if (tab === 'draw') {
                eraserMode = false;
                canvas.selection = false;
                canvas.isDrawingMode = false;
                drawingMode = true;
                detachCustomDrawListeners();
                attachCustomDrawListeners();
                setCanvasActive(true);
                    } else {
                eraserMode = false;
                canvas.selection = true;
                canvas.isDrawingMode = false;
                detachCustomDrawListeners();
                setCanvasActive(tab === 'text');
              }
            }

            var photoCount = 0;
            var bgRect = null;
            var editId = null;
            var history = [];
            var historyIndex = -1;
            var historyMax = 50;
            var isLoadingFromHistory = false;

            function findBgRect() {
              var objs = canvas.getObjects();
              for (var i = 0; i < objs.length; i++) {
                var o = objs[i];
                if (o.type === 'rect' && o.left === 0 && o.top === 0 && Math.abs(o.width - w) < 2 && Math.abs(o.height - h) < 2) return o;
              }
              return objs.find(function(o) { return o.type === 'rect' && (o.data && o.data.isBg || o.evented === false); }) || null;
            }

            function notifyHistoryState() {}
            function saveHistory() {
              if (isLoadingFromHistory) return;
              try {
                var json = JSON.stringify(canvas.toJSON());
                if (historyIndex < history.length - 1) history = history.slice(0, historyIndex + 1);
                history.push(json);
                if (history.length > historyMax) history.shift();
                historyIndex = history.length - 1;
                notifyHistoryState();
              } catch (e) {}
            }
            function loadHistoryJson(json, done) {
              try {
                canvas.loadFromJSON(json, function() {
                  bgRect = findBgRect();
                  if (bgRect) bgRect.set({ selectable: false, evented: false, erasable: false, data: Object.assign({}, bgRect.data || {}, { isBg: true }) });
                  canvas.forEachObject(function(o) { if (o !== bgRect && o.type !== 'rect') o.set({ selectable: true, evented: true, hasControls: true, lockScalingX: false, lockScalingY: false }); });
                  canvas.backgroundColor = '#FF8C00';
                  canvas.selection = true;
                  canvas.discardActiveObject();
                  canvas.requestRenderAll();
                  if (done) done();
                });
              } catch (err) {
                if (done) done();
              }
            }
            function undo() {
              if (historyIndex <= 0) return;
              isLoadingFromHistory = true;
              historyIndex--;
              var json = history[historyIndex];
              if (json) {
                loadHistoryJson(json, function() {
                  isLoadingFromHistory = false;
                  notifyHistoryState();
                });
              } else {
                isLoadingFromHistory = false;
              }
            }
            function redo() {
              if (historyIndex >= history.length - 1) return;
              isLoadingFromHistory = true;
              historyIndex++;
              var json = history[historyIndex];
              if (json) {
                loadHistoryJson(json, function() {
                  isLoadingFromHistory = false;
                  notifyHistoryState();
                });
              } else {
                isLoadingFromHistory = false;
              }
            }
            var DEFAULT_BG = '#FF8C00';
            try {
              var params = new URLSearchParams(window.location.search);
              editId = params.get('edit');
            } catch(e) {}

            function setBackground(color) {
              var fillColor = color || DEFAULT_BG;
              canvas.backgroundColor = fillColor;
              var bgInp = document.getElementById('collage-bg-color');
              if (bgInp && typeof fillColor === 'string' && fillColor.indexOf('#') === 0) bgInp.value = fillColor;
              if (bgRect) canvas.remove(bgRect);
              bgRect = new fabric.Rect({
                left: 0, top: 0, width: w, height: h,
                fill: fillColor,
                selectable: false,
                evented: false,
                erasable: false,
                excludeFromExport: false,
                data: { isBg: true }
              });
              canvas.add(bgRect);
              canvas.sendToBack(bgRect);
              canvas.discardActiveObject();
              canvas.renderAll();
            }
            var key = 'gom_hour_collages';
            var list = [];
            try { list = JSON.parse(localStorage.getItem(key) || '[]'); } catch(e) {}
            var editItem = editId ? list.find(function(x) { return x.id === editId; }) : null;

            if (editItem && editItem.canvasJson) {
              isLoadingFromHistory = true;
              canvas.loadFromJSON(editItem.canvasJson, function() {
                bgRect = findBgRect();
                if (!bgRect) bgRect = canvas.item(0);
                if (bgRect) { bgRect.set({ selectable: false, evented: false, erasable: false, data: Object.assign({}, bgRect.data || {}, { isBg: true }) }); }
                canvas.forEachObject(function(o) { if (o !== bgRect && o.type !== 'rect') o.set({ selectable: true, evented: true, hasControls: true, lockScalingX: false, lockScalingY: false }); });
                canvas.backgroundColor = '#FF8C00';
                canvas.selection = true;
                canvas.discardActiveObject();
                canvas.renderAll();
                isLoadingFromHistory = false;
                saveHistory();
              });
            } else {
              canvas.backgroundColor = '#FF8C00';
              setBackground(DEFAULT_BG);
              saveHistory();
              if (editItem && editItem.dataUrl) {
                fabric.Image.fromURL(editItem.dataUrl, function(img) {
                  if (img) {
                    var s = Math.min(size / img.width, size / img.height);
                    img.set({ scaleX: s, scaleY: s, left: 0, top: 0, selectable: true });
                    canvas.add(img);
                    canvas.sendToBack(bgRect);
                  }
                });
              }
            }

            canvas.on('selection:created', function(e) {
              if (e.selected && e.selected[0] === bgRect) {
                canvas.discardActiveObject();
                canvas.renderAll();
                return;
              }
              var obj = e.selected && e.selected[0];
              if (eraserMode && obj && obj !== bgRect) {
                canvas.remove(obj);
                canvas.discardActiveObject();
                saveHistory();
                canvas.requestRenderAll();
                return;
              }
              if (obj && (obj.type === 'i-text' || obj.type === 'text')) {
                showTextView();
                var tc = document.getElementById('collage-text-color');
                if (tc && obj.fill && typeof obj.fill === 'string' && obj.fill.indexOf('#') === 0) tc.value = obj.fill;
                updateTextSizeSlider();
              }
              if (obj && (obj.type === 'i-text' || obj.type === 'text') && obj.enterEditing && !eraserMode) {
                obj.enterEditing();
                setTimeout(function() {
                  var o = canvas.getActiveObject();
                  if (o) {
                    if (o.hiddenTextarea) o.hiddenTextarea.focus();
                    else if (canvas.upperCanvasEl) canvas.upperCanvasEl.focus();
                  }
                }, 100);
              }
            });
            canvas.on('path:created', function() {
              if (bgRect) canvas.sendToBack(bgRect);
              saveHistory();
            });
            canvas.on('object:modified', function() { saveHistory(); });
            canvas.on('object:added', function(e) {
              var o = e.target;
              if (o && o !== bgRect && o.type !== 'rect') {
                o.set({ selectable: true, evented: true, hasControls: true, lockScalingX: false, lockScalingY: false });
                saveHistory();
              }
            });
            canvas.on('object:removed', function(e) {
              if (e.target && e.target !== bgRect) saveHistory();
            });
            canvas.on('text:editing:exited', function() { saveHistory(); });
            canvas.on('selection:cleared', function() { hideTextView(); });

            var longPressTimer = null;
            var longPressTarget = null;
            function clearLongPress() {
              if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
            }
            function onPointerDown(e) {
              var target = e.target;
              if (!target || target === bgRect) { longPressTarget = true; }
            }
            function onPointerUp() {
              clearLongPress();
              longPressTarget = null;
            }
            canvas.on('mouse:down', function(e) {
              if (eraserMode && e.target && e.target !== bgRect) {
                canvas.remove(e.target);
                saveHistory();
                canvas.requestRenderAll();
                return;
              }
              if (eraserMode) return;
              onPointerDown(e);
            });
            canvas.on('mouse:up', onPointerUp);
            canvas.on('mouse:leave', onPointerUp);
            var bgColorInp = document.getElementById('collage-bg-color');
            if (bgColorInp) {
              bgColorInp.addEventListener('change', function() {
                var c = this.value;
                setBackground(c);
                saveHistory();
              });
            }

            function getSlotPositions() {
              var r = 2, c = 2;
              var slots = [];
              var pad = 8;
              var slotW = (w - pad * (c + 1)) / c;
              var slotH = (h - pad * (r + 1)) / r;
              for (var i = 0; i < r; i++) {
                for (var j = 0; j < c; j++) {
                  slots.push({
                    left: pad + j * (slotW + pad),
                    top: pad + i * (slotH + pad),
                    width: slotW,
                    height: slotH
                  });
                }
              }
              return slots;
            }

            function addImageToCanvas(url) {
              fabric.Image.fromURL(url, function(img) {
                if (!img) return;
                var slots = getSlotPositions();
                var idx = Math.min(photoCount, slots.length - 1);
                if (idx < 0) return;
                var s = slots[idx];
                var scale = Math.min(s.width / img.width, s.height / img.height);
                img.set({
                  left: s.left,
                  top: s.top,
                  scaleX: scale,
                  scaleY: scale,
                  selectable: true,
                  hasControls: true
                });
                canvas.add(img);
                canvas.sendToBack(bgRect);
                photoCount++;
              });
            }

            document.getElementById('collage-file-input').addEventListener('change', function(e) {
              var files = e.target.files || [];
              for (var i = 0; i < files.length; i++) {
                var reader = new FileReader();
                reader.onload = (function(f) { return function(ev) { addImageToCanvas(ev.target.result); }; })(files[i]);
                reader.readAsDataURL(files[i]);
              }
              e.target.value = '';
            });

            function getTextColor() {
              var inp = document.getElementById('collage-text-color');
              return inp ? inp.value : '#000000';
            }
            function doAddTextAt(left, top) {
              var col = getTextColor();
              currentDrawColor = col;
              var l = (left != null ? left : w / 2 - 40);
              var t = (top != null ? top : Math.max(20, h * 0.12));
              var text = new fabric.IText('', {
                left: l,
                top: t,
                fontSize: 26,
                fontWeight: '600',
                fill: col,
                fontFamily: 'sans-serif',
                selectable: true,
                evented: true,
                hasControls: true,
                lockScalingX: false,
                lockScalingY: false,
                shadow: { color: 'rgba(0,0,0,0.25)', blur: 2, offsetX: 1, offsetY: 1 }
              });
              canvas.add(text);
              canvas.setActiveObject(text);
              showTextView();
              updateTextSizeSlider();
              text.enterEditing();
              setTimeout(function() {
                var o = canvas.getActiveObject();
                if (o && o.hiddenTextarea) o.hiddenTextarea.focus();
              }, 100);
            }
            window.__collageAddText = function() { doAddTextAt(); };
            function showTextView() {
              if (viewMain) viewMain.style.display = 'none';
              if (viewDraw) viewDraw.style.display = 'none';
              if (viewText) viewText.style.display = 'flex';
            }
            function hideTextView() {
              if (viewMain) viewMain.style.display = 'flex';
              if (viewDraw) viewDraw.style.display = 'none';
              if (viewText) viewText.style.display = 'none';
            }
            function updateTextSizeSlider() {
              var obj = canvas.getActiveObject();
              var sl = document.getElementById('text-size-slider');
              if (sl && obj && (obj.type === 'i-text' || obj.type === 'text')) {
                sl.value = Math.min(72, Math.max(12, obj.fontSize || 24));
              }
            }

            function showSaveModal() {
              canvas.discardActiveObject();
              canvas.isDrawingMode = false;
              canvas.backgroundColor = '#FF8C00';
              canvas.renderAll();
              var modal = document.getElementById('collage-save-modal');
              var nameInp = document.getElementById('collage-save-name-input');
              if (modal && nameInp) {
                nameInp.value = (editItem && editItem.title) ? editItem.title : '';
                nameInp.placeholder = '예: 우리의 첫 보드';
                modal.style.display = 'flex';
                setTimeout(function() { nameInp.focus(); }, 50);
              }
            }
            function performSave(titleVal) {
              var dataUrl = canvas.toDataURL({ format: 'png', multiplier: 1 });
              var canvasJson = JSON.stringify(canvas.toJSON());
              var list = [];
              try { list = JSON.parse(localStorage.getItem(key) || '[]'); } catch(e) {}
              var name = (titleVal && String(titleVal).trim()) ? String(titleVal).trim() : ((function(){ var d = new Date(); return (d.getMonth()+1) + '월 ' + d.getDate() + '일'; })());
              if (editId) {
                var idx = list.findIndex(function(x) { return x.id === editId; });
                if (idx >= 0) {
                  list[idx] = { id: editId, dataUrl: dataUrl, canvasJson: canvasJson, title: name, createdAt: list[idx].createdAt || Date.now() };
                } else {
                  list.unshift({ id: 'c' + Date.now(), dataUrl: dataUrl, canvasJson: canvasJson, title: name, createdAt: Date.now() });
                }
              } else {
                list.unshift({ id: 'c' + Date.now(), dataUrl: dataUrl, canvasJson: canvasJson, title: name, createdAt: Date.now() });
              }
              localStorage.setItem(key, JSON.stringify(list));
              window.location.href = '/collage';
            }
            function doSave() {
              showSaveModal();
            }
            window.__collageSave = doSave;
            window.__collageClick.undo = function() { try { undo(); } catch(e) {} };
            window.__collageClick.redo = function() { try { redo(); } catch(e) {} };
            window.__collageClick.save = function() { try { doSave(); } catch(e) {} };
            var viewMain = document.getElementById('view-main');
            var viewDraw = document.getElementById('view-draw');
            var viewText = document.getElementById('view-text');
            var currentBrush = 'pen';
            function showMainView() { if (viewMain) viewMain.style.display = 'flex'; if (viewDraw) viewDraw.style.display = 'none'; if (viewText) viewText.style.display = 'none'; }
            function showDrawView() { if (viewMain) viewMain.style.display = 'none'; if (viewDraw) viewDraw.style.display = 'flex'; }
            var lastToolAction = 0;
            window.__collageClick.draw = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); showDrawView(); eraserMode=false; canvas.selection=false; currentBrush='pen'; setBrush('pen', getDrawColor()); setCanvasActive(true); canvas.requestRenderAll(); updateBrushUI('pen'); };
            window.__collageClick.text = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); applyTab('text'); doAddTextAt(); };
            window.__collageClick.photo = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); applyTab('photo'); var fi=document.getElementById('collage-file-input'); if(fi){fi.value='';fi.click();} };
            window.__collageClick.eraser = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); applyTab('eraser'); var eb=document.querySelector('[data-tool="eraser"]'); if(eb){eb.style.borderColor='#fbbf24';eb.style.color='#b45309';} document.querySelectorAll('[data-tool="draw"],[data-tool="text"],[data-tool="photo"]').forEach(function(b){b.style.borderColor='transparent';b.style.color='';}); };
            window.__collageClick.back = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); showMainView(); applyTab('idle'); document.querySelectorAll('[data-tool]').forEach(function(b){b.style.borderColor='';b.style.color='';}); };
            window.__collageClick.textBack = function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); var obj = canvas.getActiveObject(); if (obj && (obj.type === 'i-text' || obj.type === 'text') && obj.exitEditing) obj.exitEditing(); showMainView(); applyTab('idle'); document.querySelectorAll('[data-tool]').forEach(function(b){b.style.borderColor='';b.style.color='';}); };
            function updateBrushUI(b) { if(viewDraw){ viewDraw.querySelectorAll('[data-brush]').forEach(function(x){x.style.borderColor='#e5e7eb';x.style.borderWidth='2px';}); var sel=viewDraw.querySelector('[data-brush="'+b+'"]'); if(sel){sel.style.borderColor='#fbbf24';sel.style.borderWidth='2px';} } }
            window.__collageClick.brush = function(b) { return function() { if (Date.now()-lastToolAction<80) return; lastToolAction=Date.now(); eraserMode=false; canvas.selection=false; currentBrush=b; setBrush(currentBrush, getDrawColor()); setCanvasActive(true); canvas.requestRenderAll(); updateBrushUI(b); }; };
            window.__collageClick.undo = function() { try { undo(); } catch(e) {} };
            window.__collageClick.redo = function() { try { redo(); } catch(e) {} };
            window.__collageClick.save = function() { try { doSave(); } catch(e) {} };
            function preventDouble(handler){ var t=0; return function(e){ e.preventDefault(); e.stopPropagation(); if(Date.now()-t<300)return; t=Date.now(); try{handler();}catch(err){} }; }
            var u=document.getElementById('collage-undo-btn'); if(u){ var uh=preventDouble(undo); u.addEventListener('click',uh); u.addEventListener('touchend',uh,{passive:false}); }
            var r=document.getElementById('collage-redo-btn'); if(r){ var rh=preventDouble(redo); r.addEventListener('click',rh); r.addEventListener('touchend',rh,{passive:false}); }
            var sv=document.getElementById('collage-save-btn'); if(sv){ var svh=preventDouble(doSave); sv.addEventListener('click',svh); sv.addEventListener('touchend',svh,{passive:false}); }
            var saveModal = document.getElementById('collage-save-modal');
            var saveNameInp = document.getElementById('collage-save-name-input');
            var saveModalCancel = document.getElementById('collage-save-modal-cancel');
            var saveModalConfirm = document.getElementById('collage-save-modal-confirm');
            function closeSaveModal() { if (saveModal) saveModal.style.display = 'none'; }
            if (saveModalCancel) { saveModalCancel.addEventListener('click', closeSaveModal); saveModalCancel.addEventListener('touchend', function(e){ e.preventDefault(); closeSaveModal(); }, {passive:false}); }
            if (saveModalConfirm) {
              function onConfirm() { var name = saveNameInp ? saveNameInp.value.trim() : ''; closeSaveModal(); performSave(name); }
              saveModalConfirm.addEventListener('click', function(){ onConfirm(); });
              saveModalConfirm.addEventListener('touchend', function(e){ e.preventDefault(); onConfirm(); }, {passive:false});
            }
            if (saveModal) saveModal.addEventListener('click', function(e) { if (e.target === saveModal) closeSaveModal(); });
            if (saveNameInp) saveNameInp.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); var name = saveNameInp.value.trim(); closeSaveModal(); performSave(name); } });
            var drawColorInp = document.getElementById('draw-color-picker');
            if (drawColorInp) drawColorInp.onchange = function() { setBrush(currentBrush, this.value); };
            var textColorInp = document.getElementById('collage-text-color');
            if (textColorInp) {
              var applyTextColor = function() {
                var obj = canvas.getActiveObject();
                if (obj && (obj.type === 'i-text' || obj.type === 'text')) { obj.set('fill', textColorInp.value); canvas.requestRenderAll(); saveHistory(); }
              };
              textColorInp.oninput = textColorInp.onchange = applyTextColor;
            }
            var textSizeSlider = document.getElementById('text-size-slider');
            if (textSizeSlider) textSizeSlider.oninput = function() {
              var obj = canvas.getActiveObject();
              var v = parseInt(this.value, 10);
              if (obj && (obj.type === 'i-text' || obj.type === 'text')) { obj.set('fontSize', v); canvas.requestRenderAll(); saveHistory(); }
            };
            applyTab('idle');
            document.addEventListener('dblclick', function(e) { e.preventDefault(); }, { passive: false });
            setTimeout(function(){ notifyHistoryState(); }, 400);
            } catch (e) {
              console.error('Collage init error:', e);
              var errMsg = (e && e.message) ? e.message : String(e);
              var fail = function() { alert('보드 로드 실패: ' + errMsg); };
              window.__collageClick.draw = window.__collageClick.text = window.__collageClick.photo = window.__collageClick.eraser = window.__collageClick.back = fail;
              window.__collageClick.brush = function() { return fail; };
              window.__collageClick.undo = window.__collageClick.redo = window.__collageClick.save = fail;
            }
            }
            if (document.readyState === 'loading') {
              document.addEventListener('DOMContentLoaded', init);
            } else {
              init();
            }
          })();
        `
      }} />
    </div>,
    { title: '보드 만들기 - 곰아워', disableZoom: true }
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
    
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
    )

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

    // 상대방 앱에서 우리의 약속 표시하도록 promise_pending 설정
    try {
      await c.env.DB.prepare(
        'UPDATE users SET promise_pending = 1 WHERE couple_id = ? AND id != ?'
      ).bind(coupleId, user.db_id).run()
    } catch (e) { /* promise_pending 컬럼 없을 수 있음 */ }

    // 세션 업데이트
    user.couple_id = coupleId
    user.couple_code = couple_code
    user.gender = gender
    user.notification_time = notification_time
    if (name?.trim()) {
      user.name = name.trim()
    }
    user.setup_done = true
    
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
      sameSite: 'Lax',
    })
    )

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

// 상대방 미확인 메시지 조회 (대시보드 모달용)
app.get('/api/messages/unread', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const effectiveCoupleId = user.couple_id ?? -user.db_id

  try {
    const unreadCountRow = await c.env.DB.prepare(
      `SELECT COUNT(*) as count
       FROM messages m
       LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = ?
       WHERE m.couple_id = ? AND m.user_id != ? AND mr.id IS NULL`
    ).bind(user.db_id, effectiveCoupleId, user.db_id).first()
    const unreadTotalCount = Number(unreadCountRow?.count || 0)

    const unread = await c.env.DB.prepare(
      `SELECT m.id, m.content, m.message_date, m.created_at, u.name
       FROM messages m
       JOIN users u ON u.id = m.user_id
       LEFT JOIN message_reads mr ON mr.message_id = m.id AND mr.user_id = ?
       WHERE m.couple_id = ? AND m.user_id != ? AND mr.id IS NULL
       ORDER BY m.message_date DESC, m.created_at DESC, m.id DESC
       LIMIT 5`
    ).bind(user.db_id, effectiveCoupleId, user.db_id).all()

    const unreadMessages = (unread.results || []) as any[]
    let emptyHint: { partner_name: string; partner_gender: string } | null = null

    if (unreadMessages.length === 0 && user.couple_id) {
      const partner = await c.env.DB.prepare(
        'SELECT id, name, gender FROM users WHERE couple_id = ? AND id != ? LIMIT 1'
      ).bind(user.couple_id, user.db_id).first()

      if (partner?.id) {
        const yesterdayKst = new Intl.DateTimeFormat('en-CA', {
          timeZone: 'Asia/Seoul',
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
        }).format(new Date(Date.now() - 24 * 60 * 60 * 1000))

        const partnerWroteToday = await c.env.DB.prepare(
          'SELECT id FROM messages WHERE couple_id = ? AND user_id = ? AND message_date = ? LIMIT 1'
        ).bind(effectiveCoupleId, partner.id, yesterdayKst).first()

        if (!partnerWroteToday) {
          const partnerGender = String(partner.gender || '').trim()
          if (partnerGender === 'male' || partnerGender === 'female') {
            emptyHint = {
              partner_name: String(partner.name || '상대방'),
              partner_gender: partnerGender,
            }
          }
        }
      }
    }

    if (emptyHint) {
      try {
        const shownRow = await c.env.DB.prepare(
          'SELECT COALESCE(contract_no_msg_reminder_shown, 0) AS shown FROM users WHERE id = ?'
        )
          .bind(user.db_id)
          .first()
        if (Number(shownRow?.shown) === 1) {
          emptyHint = null
        } else {
          await c.env.DB.prepare(
            'UPDATE users SET contract_no_msg_reminder_shown = 1 WHERE id = ?'
          )
            .bind(user.db_id)
            .run()
        }
      } catch (e) {
        /* 컬럼 없을 수 있음: 마이그레이션 전에는 기존처럼 매번 힌트 반환 */
      }
    }

    return c.json({
      success: true,
      unread_messages: unreadMessages,
      unread_total_count: unreadTotalCount,
      empty_hint: emptyHint
    })
  } catch (error) {
    console.error('미확인 메시지 조회 오류:', error)
    return c.json({ success: false, error: '미확인 메시지 조회 중 오류가 발생했습니다.' }, 500)
  }
})

// 메시지 읽음 처리 (모달 오픈 시점 일괄 처리)
app.post('/api/messages/read', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const effectiveCoupleId = user.couple_id ?? -user.db_id
  const body = await c.req.json().catch(() => ({} as { message_ids?: unknown }))
  const rawIds = Array.isArray(body.message_ids) ? body.message_ids : []
  const messageIds = rawIds
    .map((id) => Number(id))
    .filter((id) => Number.isInteger(id) && id > 0)

  if (messageIds.length === 0) {
    return c.json({ success: true, read_count: 0 })
  }

  try {
    const placeholders = messageIds.map(() => '?').join(', ')
    const targetRows = await c.env.DB.prepare(
      `SELECT id FROM messages
       WHERE id IN (${placeholders}) AND couple_id = ? AND user_id != ?`
    ).bind(...messageIds, effectiveCoupleId, user.db_id).all()
    const targetIds = (targetRows.results || [])
      .map((row: any) => Number(row.id))
      .filter((id) => Number.isInteger(id) && id > 0)

    for (const messageId of targetIds) {
      await c.env.DB.prepare(
        'INSERT OR IGNORE INTO message_reads (user_id, message_id, read_at) VALUES (?, ?, CURRENT_TIMESTAMP)'
      ).bind(user.db_id, messageId).run()
    }

    return c.json({ success: true, read_count: targetIds.length })
  } catch (error) {
    console.error('메시지 읽음 처리 오류:', error)
    return c.json({ success: false, error: '메시지 읽음 처리 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 약속 메모 목록
app.get('/api/promise-notes', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const sortBy = c.req.query('sort_by') === 'priority' ? 'priority' : 'latest'
  try {
    await c.env.DB.prepare("ALTER TABLE promise_notes ADD COLUMN priority INTEGER NOT NULL DEFAULT 3").run().catch(() => {})
    const dbUser = await c.env.DB.prepare(
      'SELECT couple_id FROM users WHERE id = ?'
    ).bind(user.db_id).first()
    const coupleId = dbUser?.couple_id as number | null
    if (!coupleId) {
      return c.json({ success: true, notes: [] })
    }

    const notesSql = sortBy === 'priority'
      ? `SELECT pn.id, pn.title, pn.priority, pn.note_date, pn.content, pn.created_at, u.name as author_name
         FROM promise_notes pn
         JOIN users u ON u.id = pn.author_id
         WHERE pn.couple_id = ?
         ORDER BY pn.priority DESC, pn.note_date DESC, pn.id DESC`
      : `SELECT pn.id, pn.title, pn.priority, pn.note_date, pn.content, pn.created_at, u.name as author_name
         FROM promise_notes pn
         JOIN users u ON u.id = pn.author_id
         WHERE pn.couple_id = ?
         ORDER BY pn.note_date DESC, pn.id DESC`
    const notes = await c.env.DB.prepare(notesSql).bind(coupleId).all()

    return c.json({ success: true, notes: notes.results || [] })
  } catch (error) {
    console.error('약속 메모 조회 오류:', error)
    return c.json({ success: false, error: '약속 메모 조회 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 약속 메모 저장
app.post('/api/promise-notes', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const { title, priority, note_date, content } = await c.req.json()
  const safeTitle = String(title || '').trim()
  const safePriority = Number(priority || 3)
  const inputDate = String(note_date || '').trim()
  const safeDate = inputDate && /^\d{4}-\d{2}-\d{2}$/.test(inputDate) ? inputDate : getTodayKst()
  const safeContent = String(content || '').trim()

  if (!safeTitle || !safeContent) {
    return c.json({ success: false, error: '제목과 내용을 모두 입력해주세요.' }, 400)
  }
  if (safeTitle.length > 80) {
    return c.json({ success: false, error: '제목은 80자 이하로 입력해주세요.' }, 400)
  }
  if (safeContent.length > 2000) {
    return c.json({ success: false, error: '내용은 2000자 이하로 입력해주세요.' }, 400)
  }
  if (!Number.isInteger(safePriority) || safePriority < 1 || safePriority > 5) {
    return c.json({ success: false, error: '우선순위는 1~5 사이로 선택해주세요.' }, 400)
  }
  try {
    await c.env.DB.prepare("ALTER TABLE promise_notes ADD COLUMN priority INTEGER NOT NULL DEFAULT 3").run().catch(() => {})
    const dbUser = await c.env.DB.prepare(
      'SELECT couple_id FROM users WHERE id = ?'
    ).bind(user.db_id).first()
    const coupleId = dbUser?.couple_id as number | null
    if (!coupleId) {
      return c.json({ success: false, error: '커플 연동 후 사용할 수 있습니다.' }, 400)
    }

    await c.env.DB.prepare(
      'INSERT INTO promise_notes (couple_id, author_id, title, priority, note_date, content) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(coupleId, user.db_id, safeTitle, safePriority, safeDate, safeContent).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('약속 메모 저장 오류:', error)
    return c.json({ success: false, error: '약속 메모 저장 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 약속 메모 수정
app.put('/api/promise-notes/:id', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const noteId = Number(c.req.param('id'))
  if (!Number.isInteger(noteId) || noteId <= 0) {
    return c.json({ success: false, error: '유효하지 않은 메모입니다.' }, 400)
  }

  const { title, priority, content } = await c.req.json()
  const safeTitle = String(title || '').trim()
  const safePriority = Number(priority || 3)
  const safeContent = String(content || '').trim()

  if (!safeTitle || !safeContent) {
    return c.json({ success: false, error: '제목과 내용을 모두 입력해주세요.' }, 400)
  }
  if (safeTitle.length > 80) {
    return c.json({ success: false, error: '제목은 80자 이하로 입력해주세요.' }, 400)
  }
  if (safeContent.length > 2000) {
    return c.json({ success: false, error: '내용은 2000자 이하로 입력해주세요.' }, 400)
  }
  if (!Number.isInteger(safePriority) || safePriority < 1 || safePriority > 5) {
    return c.json({ success: false, error: '우선순위는 1~5 사이로 선택해주세요.' }, 400)
  }
  try {
    await c.env.DB.prepare("ALTER TABLE promise_notes ADD COLUMN priority INTEGER NOT NULL DEFAULT 3").run().catch(() => {})
    const dbUser = await c.env.DB.prepare(
      'SELECT couple_id FROM users WHERE id = ?'
    ).bind(user.db_id).first()
    const coupleId = dbUser?.couple_id as number | null
    if (!coupleId) {
      return c.json({ success: false, error: '커플 연동 후 사용할 수 있습니다.' }, 400)
    }

    const result = await c.env.DB.prepare(
      'UPDATE promise_notes SET title = ?, priority = ?, content = ? WHERE id = ? AND couple_id = ?'
    ).bind(safeTitle, safePriority, safeContent, noteId, coupleId).run()

    if (!(result.meta.changes && result.meta.changes > 0)) {
      return c.json({ success: false, error: '메모를 찾을 수 없습니다.' }, 404)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('약속 메모 수정 오류:', error)
    return c.json({ success: false, error: '약속 메모 수정 중 오류가 발생했습니다.' }, 500)
  }
})

// 커플 약속 메모 삭제
app.delete('/api/promise-notes/:id', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const noteId = Number(c.req.param('id'))
  if (!Number.isInteger(noteId) || noteId <= 0) {
    return c.json({ success: false, error: '유효하지 않은 메모입니다.' }, 400)
  }

  try {
    const dbUser = await c.env.DB.prepare(
      'SELECT couple_id FROM users WHERE id = ?'
    ).bind(user.db_id).first()
    const coupleId = dbUser?.couple_id as number | null
    if (!coupleId) {
      return c.json({ success: false, error: '커플 연동 후 사용할 수 있습니다.' }, 400)
    }

    const result = await c.env.DB.prepare(
      'DELETE FROM promise_notes WHERE id = ? AND couple_id = ?'
    ).bind(noteId, coupleId).run()

    if (!(result.meta.changes && result.meta.changes > 0)) {
      return c.json({ success: false, error: '메모를 찾을 수 없습니다.' }, 404)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('약속 메모 삭제 오류:', error)
    return c.json({ success: false, error: '약속 메모 삭제 중 오류가 발생했습니다.' }, 500)
  }
})

// 연속일 그룹에서 streak 보너스 계산
const INDIVIDUAL_STREAK: [number, number][] = [[3, 10], [7, 20], [14, 40], [30, 80]]
const COUPLE_STREAK: [number, number][] = [[3, 15], [7, 35], [14, 60], [30, 120]]

function findConsecutiveGroups(sortedDates: string[]): string[][] {
  const groups: string[][] = []
  let current: string[] = []
  for (const d of sortedDates) {
    if (current.length === 0) {
      current = [d]
    } else {
      const prev = current[current.length - 1]
      const prevTime = new Date(prev + 'T00:00:00').getTime()
      const currTime = new Date(d + 'T00:00:00').getTime()
      const diffDays = (currTime - prevTime) / (24 * 60 * 60 * 1000)
      if (diffDays === 1) {
        current.push(d)
      } else {
        if (current.length > 0) groups.push([...current])
        current = [d]
      }
    }
  }
  if (current.length > 0) groups.push(current)
  return groups
}

function getStreakBonuses(groups: string[][], milestones: [number, number][], labelPrefix: string): { date: string; coins: number; label: string }[] {
  const bonuses: { date: string; coins: number; label: string }[] = []
  for (const group of groups) {
    const len = group.length
    const lastDate = group[group.length - 1]
    for (const [days, coins] of milestones) {
      if (len >= days) {
        bonuses.push({ date: lastDate, coins, label: `${labelPrefix} ${days}일 연속 보너스 ${lastDate} +${coins}` })
      }
    }
  }
  return bonuses
}

function getIndividualStreakBonuses(groups: string[][], userName: string): { date: string; coins: number; label: string }[] {
  const bonuses: { date: string; coins: number; label: string }[] = []
  for (const group of groups) {
    const len = group.length
    const lastDate = group[group.length - 1]
    for (const [days, coins] of INDIVIDUAL_STREAK) {
      if (len >= days) {
        bonuses.push({ date: lastDate, coins, label: `${userName} 개인 streak ${days}일 연속 보너스 +${coins}` })
      }
    }
  }
  return bonuses
}

async function buildRewardsSummary(db: Bindings['DB'], coupleId: number, currentUserDbId: number) {
  const messages = await db.prepare(
    `SELECT m.message_date, m.user_id, u.name
     FROM messages m
     JOIN users u ON m.user_id = u.id
     WHERE m.couple_id = ?
     ORDER BY m.message_date ASC, m.user_id`
  ).bind(coupleId).all()

  const rows = (messages.results || []) as any[]
  const userIdsInCouple = [...new Set(rows.map((r: any) => r.user_id))]
  const partnerId = rows.find((r: any) => r.user_id !== currentUserDbId)?.user_id as number | undefined

  const userNames: Record<number, string> = {}
  for (const row of rows) userNames[row.user_id] = row.name || '곰'

  const byDate: Record<string, { userIds: Set<number>; names: string[] }> = {}
  for (const row of rows) {
    const d = row.message_date
    if (!byDate[d]) byDate[d] = { userIds: new Set(), names: [] }
    if (!byDate[d].userIds.has(row.user_id)) {
      byDate[d].userIds.add(row.user_id)
      byDate[d].names.push(row.name || '')
    }
  }

  const allDates = Object.keys(byDate).sort()
  let totalCoins = 0
  const history: { date: string; type: string; coins: number; label: string }[] = []

  for (const date of allDates) {
    const { userIds, names } = byDate[date]
    const count = userIds.size
    let coins = 0
    let type = ''
    let label = ''
    if (count === 1) {
      coins = 1
      type = 'solo'
      label = `${names[0]} 혼자 곰아워 보상 ${date} +1`
    } else if (count >= 2) {
      coins = 4
      type = 'together'
      label = `둘이 함께 곰아워 보상 ${date} +4`
    }
    if (coins > 0) {
      totalCoins += coins
      history.push({ date, type, coins, label })
    }
  }

  for (const uid of userIdsInCouple) {
    const userName = userNames[uid] || '곰'
    const userDates = allDates.filter((d) => byDate[d].userIds.has(uid))
    const userGroups = findConsecutiveGroups(userDates)
    const userBonuses = getIndividualStreakBonuses(userGroups, userName)
    for (const b of userBonuses) {
      totalCoins += b.coins
      history.push({ date: b.date, type: 'streak_individual', coins: b.coins, label: b.label })
    }
  }

  const togetherDates = partnerId
    ? allDates.filter((d) => byDate[d].userIds.has(currentUserDbId) && byDate[d].userIds.has(partnerId))
    : []
  const coupleGroups = findConsecutiveGroups(togetherDates)
  const coupleBonuses = getStreakBonuses(coupleGroups, COUPLE_STREAK, '커플 streak')
  for (const b of coupleBonuses) {
    totalCoins += b.coins
    history.push({ date: b.date, type: 'streak_couple', coins: b.coins, label: b.label })
  }

  await ensureJackpotTables(db)
  await ensureCareMissionTables(db)
  const draws = await db.prepare(
    `SELECT draw_date, cost FROM jackpot_draws
     WHERE couple_id = ?
     ORDER BY draw_date ASC, id ASC`
  ).bind(coupleId).all()
  const drawRows = (draws.results || []) as any[]
  for (const row of drawRows) {
    const cost = Number(row.cost || JACKPOT_COST)
    totalCoins -= cost
    history.push({
      date: String(row.draw_date || ''),
      type: 'jackpot_quote',
      coins: -cost,
      label: `사랑의 글귀 보기 ${String(row.draw_date || '')} -${cost}`,
    })
  }

  await ensureCareMissionTables(db)
  const missionEvents = await db.prepare(
    `SELECT created_at, amount, label
     FROM care_mission_events
     WHERE couple_id = ? AND user_id = ?
     ORDER BY created_at ASC, id ASC`
  ).bind(coupleId, currentUserDbId).all()
  for (const row of (missionEvents.results || []) as any[]) {
    const amount = Number(row.amount || 0)
    const rawLabel = String(row.label || '💌 사랑의 언어 미션')
    const missionKeySuffixPattern = /\s\d{4}-\d{2}-\d{2}-[AB](?=\s|$)/g
    const normalizedLabel = rawLabel
      .replace(/^비밀 배려 미션 열기/, '사랑의 언어 미션 열기')
      .replace(/^비밀 배려 미션 건너뛰기 환급/, '사랑의 언어 미션 환급')
      .replace(/^비밀 배려 미션 완료 보상/, '사랑의 언어 미션 완료')
      .replace(/^💌\s*/, '')
      .replace(missionKeySuffixPattern, (m) => m.slice(0, -2))
    totalCoins += amount
    history.push({
      date: String(row.created_at || '').slice(0, 10),
      type: 'care_mission',
      coins: amount,
      label: normalizedLabel,
    })
  }

  if (totalCoins < 0) totalCoins = 0
  history.sort((a, b) => b.date.localeCompare(a.date))
  return { totalCoins, history }
}

// 곰발바닥 코인 누적 데이터 API (기본 + streak 보너스)
app.get('/api/rewards/summary', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const dbUser = await c.env.DB.prepare('SELECT couple_id FROM users WHERE id = ?')
    .bind(user.db_id).first()
  const coupleId = dbUser?.couple_id as number | null

  if (!coupleId) {
    return c.json({ success: true, totalCoins: 0, history: [] })
  }

  try {
    const { totalCoins, history } = await buildRewardsSummary(c.env.DB, coupleId, user.db_id)
    return c.json({ success: true, totalCoins, history })
  } catch (error) {
    console.error('보상 조회 오류:', error)
    return c.json({ success: false, error: '보상 조회 중 오류가 발생했습니다.' }, 500)
  }
})

app.get('/api/jackpot/state', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureJackpotTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) {
    return c.json({ success: true, can_draw: false, reason: '커플 연결이 필요해요.', today_draw: null, saved_quotes: [] })
  }

  const coupleId = Number(dbUser.couple_id)
  const today = getTodayKst()
  const todayDrawRaw = await c.env.DB.prepare(
    `SELECT jd.id, jd.quote, jd.quote_source, jd.draw_date, jd.cost, jd.drawer_user_id, u.name AS drawer_name
     FROM jackpot_draws jd
     LEFT JOIN users u ON jd.drawer_user_id = u.id
     WHERE jd.couple_id = ? AND jd.draw_date = ?
     LIMIT 1`
  ).bind(coupleId, today).first()
  let todayDraw: any = null
  if (todayDrawRaw) {
    const savedByMeRow = await c.env.DB.prepare(
      'SELECT id FROM jackpot_saved_quotes WHERE couple_id = ? AND draw_id = ? AND saved_by_user_id = ? LIMIT 1'
    ).bind(coupleId, Number((todayDrawRaw as any).id || 0), user.db_id).first()
    const savedByAnyoneRow = await c.env.DB.prepare(
      'SELECT id FROM jackpot_saved_quotes WHERE couple_id = ? AND draw_id = ? LIMIT 1'
    ).bind(coupleId, Number((todayDrawRaw as any).id || 0)).first()
    todayDraw = {
      ...todayDrawRaw,
      quote_source: resolveQuoteSource(todayDrawRaw.quote as string, todayDrawRaw.quote_source as string),
      saved_by_me: !!savedByMeRow?.id,
      saved_by_anyone: !!savedByAnyoneRow?.id,
    }
  }

  const savedRowsRaw = await c.env.DB.prepare(
    `SELECT jsq.id, jsq.draw_id, jsq.quote, jsq.quote_source, jsq.created_at, u.name AS saver_name, jsq.saved_by_user_id
     FROM jackpot_saved_quotes jsq
     LEFT JOIN users u ON jsq.saved_by_user_id = u.id
     WHERE jsq.couple_id = ?
     ORDER BY jsq.created_at DESC, jsq.id DESC
     LIMIT 50`
  ).bind(coupleId).all()
  const savedRows = (savedRowsRaw.results || []).map((row: any) => ({
    ...row,
    quote_source: resolveQuoteSource(row.quote, row.quote_source),
    saved_by_me: Number(row.saved_by_user_id || 0) === Number(user.db_id),
  }))

  return c.json({
    success: true,
    can_draw: !todayDraw,
    reason: todayDraw ? '오늘은 이미 레버를 당겼어요.' : '',
    today_draw: todayDraw || null,
    saved_quotes: savedRows,
  })
})

app.post('/api/jackpot/draw', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureJackpotTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)

  const coupleId = Number(dbUser.couple_id)
  const today = getTodayKst()

  const existingDrawRaw = await c.env.DB.prepare(
    `SELECT jd.id, jd.quote, jd.quote_source, jd.draw_date, jd.cost, jd.drawer_user_id, u.name AS drawer_name
     FROM jackpot_draws jd
     LEFT JOIN users u ON jd.drawer_user_id = u.id
     WHERE jd.couple_id = ? AND jd.draw_date = ?
     LIMIT 1`
  ).bind(coupleId, today).first()
  let existingDraw: any = null
  if (existingDrawRaw) {
    const savedByMeRow = await c.env.DB.prepare(
      'SELECT id FROM jackpot_saved_quotes WHERE couple_id = ? AND draw_id = ? AND saved_by_user_id = ? LIMIT 1'
    ).bind(coupleId, Number((existingDrawRaw as any).id || 0), user.db_id).first()
    const savedByAnyoneRow = await c.env.DB.prepare(
      'SELECT id FROM jackpot_saved_quotes WHERE couple_id = ? AND draw_id = ? LIMIT 1'
    ).bind(coupleId, Number((existingDrawRaw as any).id || 0)).first()
    existingDraw = {
      ...existingDrawRaw,
      quote_source: resolveQuoteSource(existingDrawRaw.quote as string, existingDrawRaw.quote_source as string),
      saved_by_me: !!savedByMeRow?.id,
      saved_by_anyone: !!savedByAnyoneRow?.id,
    }
  }

  if (existingDraw) {
    return c.json({ success: true, already_drawn: true, draw: existingDraw })
  }

  const { totalCoins } = await buildRewardsSummary(c.env.DB, coupleId, user.db_id)
  if (totalCoins < JACKPOT_COST) {
    return c.json({ success: false, error: `코인이 부족해요. (필요: ${JACKPOT_COST})`, totalCoins }, 400)
  }

  const selected = LOVE_QUOTES_WITH_SOURCE[Math.floor(Math.random() * LOVE_QUOTES_WITH_SOURCE.length)] || { text: '우리의 사랑은 오늘도 자라고 있어요.', source: '출처 미상' }
  await c.env.DB.prepare(
    `INSERT INTO jackpot_draws (couple_id, drawer_user_id, quote, quote_source, draw_date, cost)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(coupleId, user.db_id, selected.text, selected.source, today, JACKPOT_COST).run()

  const created = await c.env.DB.prepare(
    `SELECT jd.id, jd.quote, jd.quote_source, jd.draw_date, jd.cost, jd.drawer_user_id, u.name AS drawer_name
     FROM jackpot_draws jd
     LEFT JOIN users u ON jd.drawer_user_id = u.id
     WHERE jd.couple_id = ? AND jd.draw_date = ?
     LIMIT 1`
  ).bind(coupleId, today).first()

  let createdDraw: any = null
  if (created) {
    createdDraw = {
      ...created,
      quote_source: resolveQuoteSource(String((created as any).quote || ''), String((created as any).quote_source || '')),
      saved_by_me: false,
      saved_by_anyone: false,
    }
  }

  return c.json({ success: true, already_drawn: false, draw: createdDraw || null })
})

app.post('/api/jackpot/save', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureJackpotTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)

  const coupleId = Number(dbUser.couple_id)
  const body = await c.req.json().catch(() => ({} as any))
  const drawId = Number(body?.draw_id || 0)
  if (!drawId) return c.json({ success: false, error: '저장할 글귀를 찾지 못했어요.' }, 400)

  const draw = await c.env.DB.prepare(
    'SELECT id, quote, quote_source FROM jackpot_draws WHERE id = ? AND couple_id = ?'
  ).bind(drawId, coupleId).first()
  if (!draw) return c.json({ success: false, error: '유효하지 않은 글귀예요.' }, 404)
  const resolvedSource = resolveQuoteSource(String(draw.quote || ''), String(draw.quote_source || ''))

  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO jackpot_saved_quotes (couple_id, draw_id, quote, quote_source, saved_by_user_id)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(coupleId, drawId, String(draw.quote || ''), resolvedSource, user.db_id).run()

  return c.json({ success: true })
})

app.post('/api/jackpot/unsave', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureJackpotTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)

  const coupleId = Number(dbUser.couple_id)
  const body = await c.req.json().catch(() => ({} as any))
  const savedId = Number(body?.saved_id || 0)
  if (!savedId) return c.json({ success: false, error: '저장 항목을 찾지 못했어요.' }, 400)

  const savedRow = await c.env.DB.prepare(
    'SELECT id, draw_id FROM jackpot_saved_quotes WHERE id = ? AND couple_id = ? LIMIT 1'
  ).bind(savedId, coupleId).first()
  if (!savedRow?.id) return c.json({ success: false, error: '이미 삭제되었거나 찾을 수 없어요.' }, 404)

  await c.env.DB.prepare(
    'DELETE FROM jackpot_saved_quotes WHERE id = ? AND couple_id = ?'
  ).bind(savedId, coupleId).run()

  return c.json({ success: true, draw_id: Number(savedRow.draw_id || 0) })
})

app.get('/api/love-language/state', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureLoveLanguageTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) {
    return c.json({ success: true, me: null, partner: null })
  }

  const coupleId = Number(dbUser.couple_id)
  const rows = await c.env.DB.prepare(
    `SELECT llr.user_id, llr.top1, llr.top2, llr.updated_at, u.name
     FROM love_language_results llr
     LEFT JOIN users u ON u.id = llr.user_id
     WHERE llr.couple_id = ?`
  ).bind(coupleId).all()

  const mine = (rows.results || []).find((row: any) => Number(row.user_id) === Number(user.db_id)) as any
  const partner = (rows.results || []).find((row: any) => Number(row.user_id) !== Number(user.db_id)) as any

  return c.json({
    success: true,
    me: mine ? { user_id: mine.user_id, name: mine.name || '나', top1: mine.top1 || '', top2: mine.top2 || '', updated_at: mine.updated_at || '' } : null,
    partner: partner ? { user_id: partner.user_id, name: partner.name || '상대', top1: partner.top1 || '', top2: partner.top2 || '', updated_at: partner.updated_at || '' } : null,
  })
})

app.post('/api/love-language/save', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureLoveLanguageTables(c.env.DB)
  const dbUser = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!dbUser?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)

  const body = await c.req.json().catch(() => ({} as any))
  const top1 = String(body?.top1 || '').trim()
  const top2 = String(body?.top2 || '').trim()
  if (!top1 || !top2) return c.json({ success: false, error: '1순위와 2순위를 입력해주세요.' }, 400)
  if (top1 === top2) return c.json({ success: false, error: '1순위와 2순위는 달라야 해요.' }, 400)

  const coupleId = Number(dbUser.couple_id)
  await c.env.DB.prepare(
    `INSERT INTO love_language_results (couple_id, user_id, top1, top2, updated_at)
     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(couple_id, user_id)
     DO UPDATE SET top1 = excluded.top1, top2 = excluded.top2, updated_at = CURRENT_TIMESTAMP`
  ).bind(coupleId, user.db_id, top1, top2).run()

  return c.json({ success: true })
})

app.get('/api/care-mission/current', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureCareMissionTables(c.env.DB)
  await ensureLoveLanguageTables(c.env.DB)

  const me = await c.env.DB.prepare('SELECT id, couple_id, name FROM users WHERE id = ?').bind(user.db_id).first()
  if (!me?.couple_id) {
    return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)
  }

  const partner = await c.env.DB.prepare(
    'SELECT id, name FROM users WHERE couple_id = ? AND id != ? LIMIT 1'
  ).bind(me.couple_id, user.db_id).first()
  if (!partner?.id) {
    return c.json({ success: false, error: '상대방 연결이 필요해요.' }, 400)
  }

  const missionWindow = getTodayMissionWindow(Number(me.couple_id))
  const missionKey = missionWindow.missionKey
  const partnerName = String(partner.name || '상대방')

  const partnerLove = await c.env.DB.prepare(
    'SELECT top1, top2 FROM love_language_results WHERE couple_id = ? AND user_id = ? LIMIT 1'
  ).bind(me.couple_id, partner.id).first()
  const partnerTop1 = String(partnerLove?.top1 || '').trim()
  const partnerTop2 = String(partnerLove?.top2 || '').trim()
  const partnerLoveReady = !!partnerTop1 && !!partnerTop2

  const scores: Record<string, number> = { words: 0, time: 0, gift: 0, service: 0, touch: 0 }
  const mapLoveToCategory = (love: string) => {
    if (love === '인정의 말') return 'words'
    if (love === '함께하는 시간') return 'time'
    if (love === '선물') return 'gift'
    if (love === '봉사') return 'service'
    if (love === '스킨십') return 'touch'
    return ''
  }

  const c1 = mapLoveToCategory(partnerTop1)
  const c2 = mapLoveToCategory(partnerTop2)
  if (c1) scores[c1] += 6
  if (c2) scores[c2] += 4

  const allPartnerMessages = await c.env.DB.prepare(
    `SELECT content
     FROM messages
     WHERE couple_id = ? AND user_id = ?
     ORDER BY message_date ASC, id ASC`
  ).bind(me.couple_id, partner.id).all()
  const joined = (allPartnerMessages.results || []).map((r: any) => String(r.content || '')).join(' ')
  const messageScores = scoreSignalsFromAllMessages(joined)
  scores.words += messageScores.words
  scores.time += messageScores.time
  scores.gift += messageScores.gift
  scores.service += messageScores.service
  scores.touch += messageScores.touch

  // 반복 방지: 최근 배정된 카테고리는 점수 페널티
  const recentAssigned = await c.env.DB.prepare(
    `SELECT mission_category
     FROM care_mission_assignments
     WHERE couple_id = ? AND user_id = ?
     ORDER BY id DESC
     LIMIT 6`
  ).bind(me.couple_id, user.db_id).all()
  const recentCats = (recentAssigned.results || []).map((r: any) => String(r.mission_category || ''))
  if (recentCats[0] && scores[recentCats[0] as keyof typeof scores] != null) {
    scores[recentCats[0] as keyof typeof scores] -= 8
  }
  if (recentCats[1] && scores[recentCats[1] as keyof typeof scores] != null) {
    scores[recentCats[1] as keyof typeof scores] -= 6
  }
  for (const cat of recentCats.slice(2)) {
    if (scores[cat as keyof typeof scores] != null) {
      scores[cat as keyof typeof scores] -= 2
    }
  }

  // 완료율 기반 가중치: 잘 수행하는 카테고리를 조금 더 추천
  const perfRows = await c.env.DB.prepare(
    `SELECT mission_category,
            SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed_cnt,
            SUM(CASE WHEN opened_at IS NOT NULL THEN 1 ELSE 0 END) AS opened_cnt
     FROM care_mission_assignments
     WHERE couple_id = ? AND user_id = ?
     GROUP BY mission_category`
  ).bind(me.couple_id, user.db_id).all()
  for (const row of (perfRows.results || []) as any[]) {
    const cat = String(row.mission_category || '') as keyof typeof scores
    if (!(cat in scores)) continue
    const openedCnt = Number(row.opened_cnt || 0)
    if (openedCnt <= 0) continue
    const completedCnt = Number(row.completed_cnt || 0)
    const rate = completedCnt / openedCnt
    if (rate >= 0.7) scores[cat] += 3
    else if (rate >= 0.4) scores[cat] += 1
    else scores[cat] -= 1
  }

  let assignment: any = null
  if (missionWindow.isMissionDay && partnerLoveReady) {
    assignment = await c.env.DB.prepare(
    `SELECT id, mission_key, mission_category, mission_title, mission_body, opened_at, skipped_at, completed_at
     FROM care_mission_assignments
     WHERE couple_id = ? AND user_id = ? AND mission_key = ?
     LIMIT 1`
    ).bind(me.couple_id, user.db_id, missionKey).first()

    if (!assignment) {
      const recentForTone = (allPartnerMessages.results || []).slice(-20).map((r: any) => String(r.content || '')).join(' ')
      const tone = getMissionToneFromRecentMessages(recentForTone) as 'comfort' | 'warm' | 'light'
      const generatedRaw = buildMissionFromSignals(scores, partnerName, missionKey)
      const generated = {
        ...generatedRaw,
        body: applyMissionTone(generatedRaw.body, tone),
      }
      await c.env.DB.prepare(
        `INSERT INTO care_mission_assignments
          (couple_id, user_id, partner_user_id, mission_key, mission_category, mission_title, mission_body)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(me.couple_id, user.db_id, partner.id, missionKey, generated.category, generated.title, generated.body).run()
      assignment = await c.env.DB.prepare(
        `SELECT id, mission_key, mission_category, mission_title, mission_body, opened_at, skipped_at, completed_at
         FROM care_mission_assignments
         WHERE couple_id = ? AND user_id = ? AND mission_key = ?
         LIMIT 1`
      ).bind(me.couple_id, user.db_id, missionKey).first()
    }
  }

  const partnerNotice = await c.env.DB.prepare(
    `SELECT cmc.id, cmc.mission_title, u.name AS actor_name
     FROM care_mission_assignments cmc
     JOIN users u ON u.id = cmc.user_id
     WHERE cmc.partner_user_id = ? AND cmc.seen_by_partner = 0 AND cmc.completed_at IS NOT NULL
     ORDER BY cmc.completed_at DESC, cmc.id DESC
     LIMIT 1`
  ).bind(user.db_id).first()

  return c.json({
    success: true,
    mission: missionWindow.isMissionDay && assignment ? {
      mission_key: missionKey,
      title: String(assignment.mission_title || '배려 미션'),
      body: String(assignment.mission_body || ''),
      based_on: `최근 곰아워 기록 + ${partnerName} 사랑의 언어(${partnerTop1 || '미설정'}${partnerTop2 ? ', ' + partnerTop2 : ''})`,
      opened_by_me: !!assignment.opened_at,
      skipped_by_me: !!assignment.skipped_at,
      completed_by_me: !!assignment.completed_at,
      available_now: true,
      open_cost: CARE_MISSION_OPEN_COST,
      complete_reward: CARE_MISSION_COMPLETE_REWARD,
    } : null,
    partner_notice: partnerNotice
      ? { id: Number((partnerNotice as any).id || 0), actor_name: String((partnerNotice as any).actor_name || '상대방'), mission_title: String((partnerNotice as any).mission_title || '') }
      : null,
  })
})

app.post('/api/care-mission/open', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)
  await ensureCareMissionTables(c.env.DB)

  const me = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!me?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)
  const body = await c.req.json().catch(() => ({} as any))
  const missionKey = String(body?.mission_key || '').trim()
  if (!missionKey) return c.json({ success: false, error: '미션 키가 필요해요.' }, 400)

  const assignment = await c.env.DB.prepare(
    `SELECT id, opened_at, completed_at, skipped_at, mission_title
     FROM care_mission_assignments WHERE couple_id = ? AND user_id = ? AND mission_key = ? LIMIT 1`
  ).bind(me.couple_id, user.db_id, missionKey).first()
  if (!assignment?.id) return c.json({ success: false, error: '미션을 찾을 수 없어요.' }, 404)
  if (assignment.opened_at) return c.json({ success: true, already_opened: true })
  if (assignment.completed_at) return c.json({ success: false, error: '이미 완료한 미션이에요.' }, 400)

  const rewards = await buildRewardsSummary(c.env.DB, Number(me.couple_id), user.db_id)
  if (rewards.totalCoins < CARE_MISSION_OPEN_COST) {
    return c.json({ success: false, error: `코인이 부족해요. (필요: ${CARE_MISSION_OPEN_COST})` }, 400)
  }

  await c.env.DB.prepare(
    'UPDATE care_mission_assignments SET opened_at = CURRENT_TIMESTAMP, skipped_at = NULL WHERE id = ?'
  ).bind(assignment.id).run()
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO care_mission_events (couple_id, user_id, mission_key, event_type, amount, label)
     VALUES (?, ?, ?, 'open', ?, ?)`
  ).bind(me.couple_id, user.db_id, missionKey, -CARE_MISSION_OPEN_COST, `사랑의 언어 미션 열기 ${missionKey} -${CARE_MISSION_OPEN_COST}`).run()

  return c.json({ success: true })
})

app.post('/api/care-mission/skip', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)
  await ensureCareMissionTables(c.env.DB)

  const me = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!me?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)
  const body = await c.req.json().catch(() => ({} as any))
  const missionKey = String(body?.mission_key || '').trim()
  if (!missionKey) return c.json({ success: false, error: '미션 키가 필요해요.' }, 400)

  const assignment = await c.env.DB.prepare(
    `SELECT id, opened_at, skipped_at, completed_at
     FROM care_mission_assignments WHERE couple_id = ? AND user_id = ? AND mission_key = ? LIMIT 1`
  ).bind(me.couple_id, user.db_id, missionKey).first()
  if (!assignment?.id) return c.json({ success: false, error: '미션을 찾을 수 없어요.' }, 404)
  if (!assignment.opened_at) return c.json({ success: false, error: '먼저 미션을 열어주세요.' }, 400)
  if (assignment.completed_at) return c.json({ success: false, error: '이미 완료된 미션은 건너뛸 수 없어요.' }, 400)
  if (assignment.skipped_at) return c.json({ success: true, already_skipped: true })

  await c.env.DB.prepare(
    'UPDATE care_mission_assignments SET skipped_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(assignment.id).run()
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO care_mission_events (couple_id, user_id, mission_key, event_type, amount, label)
     VALUES (?, ?, ?, 'skip_refund', ?, ?)`
  ).bind(me.couple_id, user.db_id, missionKey, CARE_MISSION_OPEN_COST, `사랑의 언어 미션 환급 ${missionKey} +${CARE_MISSION_OPEN_COST}`).run()

  return c.json({ success: true })
})

app.post('/api/care-mission/complete', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureCareMissionTables(c.env.DB)
  await ensureLoveLanguageTables(c.env.DB)

  const me = await c.env.DB.prepare('SELECT id, couple_id FROM users WHERE id = ?').bind(user.db_id).first()
  if (!me?.couple_id) return c.json({ success: false, error: '커플 연결이 필요해요.' }, 400)
  const partner = await c.env.DB.prepare(
    'SELECT id, name FROM users WHERE couple_id = ? AND id != ? LIMIT 1'
  ).bind(me.couple_id, user.db_id).first()
  if (!partner?.id) return c.json({ success: false, error: '상대방 연결이 필요해요.' }, 400)

  const body = await c.req.json().catch(() => ({} as any))
  const missionKey = String(body?.mission_key || '').trim()
  if (!missionKey) return c.json({ success: false, error: '미션 키가 없어요.' }, 400)

  const safeMissionKey = missionKey

  const assignment = await c.env.DB.prepare(
    `SELECT id, opened_at, skipped_at, completed_at
     FROM care_mission_assignments WHERE couple_id = ? AND user_id = ? AND mission_key = ? LIMIT 1`
  ).bind(me.couple_id, user.db_id, safeMissionKey).first()
  if (!assignment?.id) return c.json({ success: false, error: '미션을 찾을 수 없어요.' }, 404)
  if (!assignment.opened_at) return c.json({ success: false, error: '먼저 미션을 열어주세요.' }, 400)
  if (assignment.skipped_at) return c.json({ success: false, error: '건너뛴 미션은 완료 처리할 수 없어요.' }, 400)
  if (assignment.completed_at) return c.json({ success: true, already_completed: true })

  await c.env.DB.prepare(
    `UPDATE care_mission_assignments
     SET completed_at = CURRENT_TIMESTAMP, seen_by_partner = 0, seen_at = NULL
     WHERE id = ?`
  ).bind(assignment.id).run()
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO care_mission_events (couple_id, user_id, mission_key, event_type, amount, label)
     VALUES (?, ?, ?, 'complete_reward', ?, ?)`
  ).bind(me.couple_id, user.db_id, safeMissionKey, CARE_MISSION_COMPLETE_REWARD, `사랑의 언어 미션 완료 ${safeMissionKey} +${CARE_MISSION_COMPLETE_REWARD}`).run()

  return c.json({ success: true })
})

app.post('/api/care-mission/notice-seen', async (c) => {
  const user = await getValidUserSession(c)
  if (!user) return c.json({ error: 'Not authenticated' }, 401)

  await ensureCareMissionTables(c.env.DB)

  const body = await c.req.json().catch(() => ({} as any))
  const completionId = Number(body?.completion_id || 0)
  if (!completionId) return c.json({ success: false, error: '알림 정보를 찾을 수 없어요.' }, 400)

  await c.env.DB.prepare(
    `UPDATE care_mission_assignments
     SET seen_by_partner = 1, seen_at = CURRENT_TIMESTAMP
     WHERE id = ? AND partner_user_id = ?`
  ).bind(completionId, user.db_id).run()

  return c.json({ success: true })
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

    // 세션 쿠키 업데이트 (path/domain 일치해야 기존 쿠키 덮어씀)
    user.name = name.trim()
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
        path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
        sameSite: 'Lax',
    })
    )

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
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
        path: '/',
        httpOnly: true,
        secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
        sameSite: 'Lax',
      })
    )
    if (user.email === 'admin@gomawo.app') {
      deleteCookie(c, 'admin_force_setup', withPublicCookieDomain(c.req.url, { path: '/' }))
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
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
      path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
        sameSite: 'Lax',
    })
    )

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

// 사용자 앱 잠금 비밀번호 해지
app.post('/api/user/clear-password', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)

  try {
    await c.env.DB.prepare(
      'UPDATE users SET pin = NULL WHERE id = ?'
    ).bind(user.db_id).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('비밀번호 해지 오류:', error)
    return c.json({ success: false, error: '비밀번호 해지 중 오류가 발생했습니다.' }, 500)
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

// 푸시 디버그 (상태 확인용)
app.get('/api/push/debug', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const tokens = await c.env.DB.prepare(
    'SELECT token, created_at FROM device_tokens WHERE user_id = ?'
  ).bind(user.db_id).all()

  const tokenRows = (tokens.results || []) as { token: string; created_at: string }[]
  const hasApnsKey = !!c.env.APNS_PRIVATE_KEY
  const useSandbox = c.env.APNS_USE_SANDBOX === 'true'

  return c.json({
    tokenCount: tokenRows.length,
    hasApnsKey,
    useSandbox,
    apnsServer: useSandbox ? 'api.sandbox.push.apple.com' : 'api.push.apple.com',
    hint: !hasApnsKey
      ? 'APNS_PRIVATE_KEY 시크릿이 없습니다. npx wrangler secret put APNS_PRIVATE_KEY -c wrangler-legacy.toml'
      : tokenRows.length === 0
        ? '토큰 없음. 설정/대시보드 진입 후 알림 허용 필요.'
        : useSandbox
          ? 'TestFlight/debug 빌드면 OK. App Store 빌드면 APNS_USE_SANDBOX=false로 변경 후 배포.'
          : 'App Store 빌드용. TestFlight면 APNS_USE_SANDBOX=true로 변경.',
    tokens: tokenRows.map(r => ({ prefix: r.token.substring(0, 16) + '...', created_at: r.created_at }))
  })
})

// 푸시 테스트 (수동 발송 - 디버깅용)
// ?tryBoth=1 이면 sandbox와 production 둘 다 시도
app.post('/api/push/test', async (c) => {
  const userSessionCookie = getCookie(c, 'user_session')
  if (!userSessionCookie) {
    return c.json({ success: false, error: '로그인이 필요합니다.' }, 401)
  }

  const user: User = JSON.parse(userSessionCookie)
  const tryBoth = c.req.query('tryBoth') === '1'

  try {
    const tokens = await c.env.DB.prepare(
      'SELECT token FROM device_tokens WHERE user_id = ?'
    ).bind(user.db_id).all()

    const tokenRows = (tokens.results || []) as { token: string }[]
    if (tokenRows.length === 0) {
      return c.json({ success: false, error: '등록된 디바이스 토큰이 없습니다. 앱을 완전히 종료 후 다시 켜고, 설정 화면에 들어온 뒤 다시 시도해주세요.' })
    }

    const results: { token: string; success: boolean; status?: number; error?: string; sandbox?: boolean }[] = []

    const sendWithSandbox = async (token: string, useSandbox: boolean) => {
      const response = await sendApns(c.env, token, '🧪 푸시 테스트 - 곰아워가 잘 되나요?', useSandbox)
      const errorText = await response.text()
      return { response, errorText, useSandbox }
    }

    for (const row of tokenRows) {
      if (tryBoth) {
        const [sandboxRes, prodRes] = await Promise.all([
          sendWithSandbox(row.token, true),
          sendWithSandbox(row.token, false)
        ])
        const sandboxOk = sandboxRes.response.ok
        const prodOk = prodRes.response.ok
        results.push({
          token: row.token.substring(0, 20) + '...',
          success: sandboxOk || prodOk,
          status: sandboxOk ? sandboxRes.response.status : prodRes.response.status,
          error: sandboxOk ? undefined : `sandbox: ${sandboxRes.response.status} ${sandboxRes.errorText} | production: ${prodRes.response.status} ${prodRes.errorText}`,
          sandbox: sandboxOk
        })
      } else {
        const { response, errorText } = await sendWithSandbox(row.token, c.env.APNS_USE_SANDBOX === 'true')
        results.push({
          token: row.token.substring(0, 20) + '...',
          success: response.ok,
          status: response.status,
          error: response.ok ? undefined : `APNs ${response.status}: ${errorText}`
        })
      }
    }

    const allOk = results.every(r => r.success)
    return c.json({
      success: allOk,
      message: allOk ? '푸시 전송 성공!' : '실패. error 필드 확인.',
      results,
      config: { useSandbox: c.env.APNS_USE_SANDBOX === 'true' },
      hint: '실패 시: /api/push/debug 로 상태 확인. tryBoth=1 로 sandbox/production 둘 다 시도 가능.'
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
    setCookie(
      c,
      'user_session',
      JSON.stringify(user),
      withPublicCookieDomain(c.req.url, {
        path: '/',
      httpOnly: true,
      secure: false,
        maxAge: SESSION_COOKIE_MAX_AGE,
        sameSite: 'Lax',
    })
    )

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
      deleteCookie(c, 'user_session', withPublicCookieDomain(c.req.url, { path: '/' }))
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

    deleteCookie(c, 'user_session', withPublicCookieDomain(c.req.url, { path: '/' }))

    return c.json({ success: true })
  } catch (error) {
    console.error('계정 삭제 오류:', error)
    return c.json({ success: false, error: '계정 삭제 중 오류가 발생했습니다.' }, 500)
  }
})

// 로그아웃
app.get('/logout', (c) => {
  deleteCookie(c, 'user_session', withPublicCookieDomain(c.req.url, { path: '/' }))
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

const sendApns = async (env: Bindings, token: string, body: string, forceSandbox?: boolean) => {
  const jwt = await createApnsJwt(env)
  const topic = env.APNS_BUNDLE_ID || 'com.gomhour.gomawo'
  const useSandbox = forceSandbox !== undefined ? forceSandbox : env.APNS_USE_SANDBOX === 'true'
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
