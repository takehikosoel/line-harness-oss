'use client'

import { useEffect, useState } from 'react'
import Header from '@/components/layout/header'
import { api, ApiError } from '@/lib/api'

export default function AccountPage() {
  const [envOwner, setEnvOwner] = useState<boolean | null>(null)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [passwordConfirmation, setPasswordConfirmation] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    void api.staff.me()
      .then((res) => {
        setEnvOwner(res.success && res.data.id === 'env-owner')
      })
      .catch(() => {
        setError('アカウント情報を取得できませんでした')
      })
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setMessage('')

    if (newPassword !== passwordConfirmation) {
      setError('新しいパスワードが一致しません')
      return
    }

    setLoading(true)
    try {
      const res = await api.auth.changePassword(
        currentPassword || undefined,
        newPassword,
      )
      if (res.success) {
        setCurrentPassword('')
        setNewPassword('')
        setPasswordConfirmation('')
        setMessage('パスワードを変更しました')
      } else {
        setError(res.error)
      }
    } catch (err) {
      if (err instanceof ApiError && err.serverMessage) {
        setError(err.serverMessage)
      } else {
        setError('パスワードの変更に失敗しました')
      }
    } finally {
      setLoading(false)
    }
  }

  // envOwner が確定するまではフォームを出さない。その間の error は
  // フォーム内に置いても描画されないので、ここで表示する。
  let content = error
    ? <p className="text-sm text-red-600">{error}</p>
    : <p className="text-sm text-gray-500">読み込み中...</p>

  if (envOwner) {
    content = (
      <p className="text-sm text-gray-700">
        環境変数のオーナーアカウントではパスワードを設定できません
      </p>
    )
  } else if (envOwner === false) {
    content = (
      <form onSubmit={handleSubmit} className="space-y-4">
        <p className="text-sm text-gray-500">
          初回設定で現在のパスワードがない場合は、空欄でかまいません。
        </p>

        <label className="block text-sm font-medium text-gray-700">
          現在のパスワード
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500"
          />
        </label>

        <label className="block text-sm font-medium text-gray-700">
          新しいパスワード
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500"
          />
        </label>

        <label className="block text-sm font-medium text-gray-700">
          新しいパスワード（確認）
          <input
            type="password"
            value={passwordConfirmation}
            onChange={(e) => setPasswordConfirmation(e.target.value)}
            className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500"
          />
        </label>

        {error && <p className="text-sm text-red-600">{error}</p>}
        {message && <p className="text-sm text-green-700">{message}</p>}

        <button
          disabled={loading || !newPassword || !passwordConfirmation}
          className="px-4 py-2 text-white rounded-lg disabled:opacity-50"
          style={{ backgroundColor: '#06C755' }}
        >
          {loading ? '変更中...' : 'パスワードを変更'}
        </button>
      </form>
    )
  }

  return (
    <div>
      <Header title="パスワード変更" />
      <div className="max-w-xl bg-white border border-gray-200 rounded-lg shadow-sm p-6">
        {content}
      </div>
    </div>
  )
}
