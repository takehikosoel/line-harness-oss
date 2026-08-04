'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'

type LoginBody =
  | { email: string; password: string }
  | { apiKey: string }

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  const login = async (body: LoginBody, apiKeyMode = false) => {
    setLoading(true)
    setError('')

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL
      if (!apiUrl) {
        setError('NEXT_PUBLIC_API_URL is not set in build env')
        return
      }

      const res = await fetch(`${apiUrl}/api/auth/login`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (res.ok) {
        localStorage.removeItem('lh_api_key')
        try {
          const data = await res.json()
          if (data.success && data.data) {
            localStorage.setItem('lh_staff_name', data.data.name)
            localStorage.setItem('lh_staff_role', data.data.role)
          }
          if (data.csrfToken) {
            localStorage.setItem('lh_csrf', data.csrfToken)
          }
        } catch {
          // Profile / CSRF caching is best-effort.
        }
        router.push('/')
        return
      }

      if (res.status === 401) {
        setError(
          apiKeyMode
            ? 'APIキーが正しくありません'
            : 'メールアドレスまたはパスワードが正しくありません',
        )
      } else if (res.status === 429) {
        setError('試行回数が多すぎます。しばらく待ってから再度お試しください')
      } else {
        const data = await res.json().catch(() => null)
        setError(data?.error ?? 'ログインに失敗しました')
      }
    } catch {
      setError('接続に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  const handlePasswordLogin = (e: React.FormEvent) => {
    e.preventDefault()
    void login({ email, password })
  }

  const handleApiKeyLogin = (e: React.FormEvent) => {
    e.preventDefault()
    void login({ apiKey }, true)
  }

  const inputClass =
    'w-full px-4 py-3 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent'

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: '#06C755' }}
    >
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-sm">
        <div className="text-center mb-6">
          <div
            className="w-12 h-12 rounded-xl flex items-center justify-center text-white font-bold text-lg mx-auto mb-3"
            style={{ backgroundColor: '#06C755' }}
          >
            H
          </div>
          <h1 className="text-xl font-bold text-gray-900">L Harness</h1>
          <p className="text-sm text-gray-500 mt-1">管理画面にログイン</p>
        </div>

        <form onSubmit={handlePasswordLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              メールアドレス
            </label>
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={inputClass}
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              パスワード
            </label>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClass}
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            disabled={loading || !email || !password}
            className="w-full py-3 text-white font-medium rounded-lg disabled:opacity-50"
            style={{ backgroundColor: '#06C755' }}
          >
            {loading ? 'ログイン中...' : 'ログイン'}
          </button>
        </form>

        <details className="mt-6 border-t border-gray-200 pt-4">
          <summary className="text-sm text-gray-600 cursor-pointer">
            API キーでログイン
          </summary>
          <form onSubmit={handleApiKeyLogin} className="mt-4 space-y-3">
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="APIキーを入力"
              className={inputClass}
            />
            <button
              disabled={loading || !apiKey}
              className="w-full py-2.5 text-white font-medium rounded-lg disabled:opacity-50"
              style={{ backgroundColor: '#06C755' }}
            >
              API キーでログイン
            </button>
          </form>
        </details>
      </div>
    </div>
  )
}
