import { ref } from 'vue'

const _username = ref('')

let checkPromise: Promise<boolean> | null = null

export function useAuth() {
  async function checkSession(): Promise<boolean> {
    if (checkPromise) return checkPromise
    if (_username.value) return true

    checkPromise = (async () => {
      try {
        const res = await fetch('/api/me', { credentials: 'include' })
        if (!res.ok) {
          _username.value = ''
          return false
        }
        const data = await res.json()
        _username.value = data.username || ''
        return true
      } catch {
        _username.value = ''
        return false
      } finally {
        checkPromise = null
      }
    })()

    return checkPromise
  }

  async function login(username: string, password: string): Promise<void> {
    const res = await fetch('/api/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `Login failed (${res.status})`)
    }
    _username.value = username
  }

  async function signup(username: string, email: string, password: string): Promise<void> {
    const res = await fetch('/api/signup', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `Signup failed (${res.status})`)
    }
    _username.value = username
  }

  async function logout(): Promise<void> {
    await fetch('/api/logout', {
      method: 'POST',
      credentials: 'include',
    })
    _username.value = ''
  }

  return {
    username: _username,
    checkSession,
    login,
    signup,
    logout,
  }
}
