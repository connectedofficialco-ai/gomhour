import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import type { Bindings, KakaoUser } from '../types'

const kakaoAuth = new Hono<{ Bindings: Bindings }>()

// 카카오 로그인 시작 - OAuth 인증 페이지로 리다이렉트
kakaoAuth.get('/login', (c) => {
  const clientId = c.env.KAKAO_CLIENT_ID
  const redirectUri = c.env.KAKAO_REDIRECT_URI
  
  if (!clientId || !redirectUri) {
    return c.json({ error: '카카오 OAuth 설정이 올바르지 않습니다.' }, 500)
  }

  const authUrl = new URL('https://kauth.kakao.com/oauth/authorize')
  authUrl.searchParams.set('client_id', clientId)
  authUrl.searchParams.set('redirect_uri', redirectUri)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('scope', 'profile_nickname,profile_image,account_email')

  return c.redirect(authUrl.toString())
})

// 카카오 OAuth 콜백 처리
kakaoAuth.get('/callback', async (c) => {
  const code = c.req.query('code')
  const error = c.req.query('error')

  if (error) {
    setCookie(c, 'from_app', '1', { path: '/', domain: 'gom-hr.com', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
    return c.redirect(`/app/login?error=${encodeURIComponent('카카오 로그인이 취소되었습니다.')}`)
  }

  if (!code) {
    setCookie(c, 'from_app', '1', { path: '/', domain: 'gom-hr.com', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
    return c.redirect(`/app/login?error=${encodeURIComponent('인증 코드가 없습니다.')}`)
  }

  try {
    // 1. 액세스 토큰 교환
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: c.env.KAKAO_CLIENT_ID,
      redirect_uri: c.env.KAKAO_REDIRECT_URI,
      code,
    })

    // 클라이언트 시크릿이 있으면 추가
    if (c.env.KAKAO_CLIENT_SECRET) {
      tokenParams.set('client_secret', c.env.KAKAO_CLIENT_SECRET)
    }

    console.log('🔑 Kakao Token Request:', {
      client_id: c.env.KAKAO_CLIENT_ID,
      redirect_uri: c.env.KAKAO_REDIRECT_URI,
      has_secret: !!c.env.KAKAO_CLIENT_SECRET,
      code_length: code.length
    })

    const tokenResponse = await fetch('https://kauth.kakao.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenParams,
    })

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text()
      console.error('❌ Kakao Token exchange failed:', {
        status: tokenResponse.status,
        statusText: tokenResponse.statusText,
        errorData,
        clientId: c.env.KAKAO_CLIENT_ID,
        redirectUri: c.env.KAKAO_REDIRECT_URI
      })
      setCookie(c, 'from_app', '1', { path: '/', domain: 'gom-hr.com', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
      return c.redirect(`/app/login?error=${encodeURIComponent('카카오 로그인에 실패했습니다.')}`)
    }

    const tokenData = await tokenResponse.json() as { access_token: string }
    const accessToken = tokenData.access_token

    // 2. 사용자 정보 가져오기
    const userResponse = await fetch('https://kapi.kakao.com/v2/user/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
      },
    })

    if (!userResponse.ok) {
      setCookie(c, 'from_app', '1', { path: '/', domain: 'gom-hr.com', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
      return c.redirect(`/app/login?error=${encodeURIComponent('사용자 정보를 가져오지 못했습니다.')}`)
    }

    const kakaoUser = await userResponse.json() as KakaoUser

    // 3. 데이터베이스에 사용자 저장 또는 업데이트
    const kakaoId = kakaoUser.id.toString()
    const email = kakaoUser.kakao_account.email || `kakao_${kakaoUser.id}@kakao.user`
    const name = kakaoUser.kakao_account.profile.nickname || kakaoUser.properties.nickname
    const picture = kakaoUser.kakao_account.profile.profile_image_url || kakaoUser.properties.profile_image

    // 기존 사용자 확인
    const existingUser = await c.env.DB.prepare(
      'SELECT * FROM users WHERE kakao_id = ?'
    ).bind(kakaoId).first()

    let userId: number
    let coupleId: number | null = null
    let coupleCode: string | null = null
    let gender: string | null = null
    let notificationTime = '20:00'
    let isAdmin = false

    if (existingUser) {
      // 기존 사용자 업데이트
      userId = existingUser.id as number
      coupleId = existingUser.couple_id as number | null
      gender = existingUser.gender as string | null
      notificationTime = existingUser.notification_time as string || '20:00'
      isAdmin = (existingUser.is_admin as number | null) === 1
      
      await c.env.DB.prepare(
        'UPDATE users SET email = ?, name = ?, picture = ? WHERE id = ?'
      ).bind(email, name, picture, userId).run()

      // 커플 코드 조회
      if (coupleId) {
        const couple = await c.env.DB.prepare(
          'SELECT couple_code FROM couples WHERE id = ?'
        ).bind(coupleId).first()
        if (couple) {
          coupleCode = couple.couple_code as string
        }
      }
    } else {
      // 신규 사용자 생성
      const result = await c.env.DB.prepare(
        'INSERT INTO users (kakao_id, email, name, picture) VALUES (?, ?, ?, ?)'
      ).bind(kakaoId, email, name, picture).run()
      
      userId = result.meta.last_row_id as number
    }

    // 4. 세션 쿠키 생성
    const setupDone = !!(gender && notificationTime)
    const userSession = {
      id: kakaoId,
      db_id: userId,
      email,
      name,
      picture,
      provider: 'kakao',
      couple_id: coupleId,
      couple_code: coupleCode,
      gender,
      notification_time: notificationTime,
      setup_done: setupDone,
      is_admin: isAdmin
    }

    // 쿠키를 gom-hr.com 도메인으로 설정 (apex·www 공유, 콜백 후 www 리다이렉트 시 전달)
    setCookie(c, 'user_session', JSON.stringify(userSession), {
      path: '/',
      domain: 'gom-hr.com',
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 24 * 7,
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
    console.error('Kakao OAuth error:', error)
    setCookie(c, 'from_app', '1', { path: '/', domain: 'gom-hr.com', httpOnly: false, maxAge: 60 * 60 * 24 * 365, sameSite: 'Lax' })
    return c.redirect(`/app/login?error=${encodeURIComponent('로그인 처리 중 오류가 발생했습니다.')}`)
  }
})

export default kakaoAuth
