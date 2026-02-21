// Cloudflare Workers 환경 변수 타입 정의
export type Bindings = {
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
  GOOGLE_REDIRECT_URI: string
  APPLE_CLIENT_ID?: string
  APPLE_TEAM_ID?: string
  APPLE_KEY_ID?: string
  APPLE_PRIVATE_KEY?: string
  APPLE_REDIRECT_URI?: string
  KAKAO_CLIENT_ID: string
  KAKAO_CLIENT_SECRET: string
  KAKAO_REDIRECT_URI: string
  JWT_SECRET: string
  RESEND_API_KEY?: string
  RESEND_FROM?: string
  FEEDBACK_TO?: string
  APNS_TEAM_ID?: string
  APNS_KEY_ID?: string
  APNS_PRIVATE_KEY?: string
  APNS_BUNDLE_ID?: string
  APNS_USE_SANDBOX?: string
  DB: D1Database
}

// 사용자 정보 타입
export interface User {
  id: string
  db_id: number
  email: string
  name: string
  picture?: string
  provider: 'google' | 'kakao' | 'local' | 'apple'
  gender?: 'male' | 'female'
  couple_id?: number
  couple_code?: string
  notification_time?: string
  is_admin?: boolean
  setup_done?: boolean
}

// Google OAuth 사용자 정보
export interface GoogleUser {
  id: string
  email: string
  verified_email: boolean
  name: string
  given_name: string
  family_name: string
  picture: string
  locale: string
}

// 카카오 OAuth 사용자 정보
export interface KakaoUser {
  id: number
  connected_at: string
  properties: {
    nickname: string
    profile_image?: string
    thumbnail_image?: string
  }
  kakao_account: {
    profile_nickname_needs_agreement: boolean
    profile: {
      nickname: string
      thumbnail_image_url?: string
      profile_image_url?: string
    }
    has_email: boolean
    email_needs_agreement: boolean
    is_email_valid?: boolean
    is_email_verified?: boolean
    email?: string
  }
}

// 커플 정보 타입
export interface Couple {
  id: number
  couple_code: string
  created_at: string
}

// 메시지 타입
export interface Message {
  id: number
  user_id: number
  couple_id: number
  content: string
  message_date: string
  created_at: string
}

// 데이터베이스 사용자 타입
export interface DBUser {
  id: number
  kakao_id: string
  apple_id?: string
  email: string
  name: string
  picture?: string
  gender?: 'male' | 'female'
  couple_id?: number
  notification_time: string
  created_at: string
  is_admin?: number
}
