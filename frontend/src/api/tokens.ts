export interface Token {
  clientID: string
  clientSecret: string
  domain: string
  public: boolean
  describe: string
  userID: string
}

export interface TokenForm {
  domain: string
  public: boolean
  describe?: string
  userId?: string
}

const BASE = '/api'

async function checkAuth(): Promise<void> {
  const res = await fetch(`${BASE}/me`, { credentials: 'include' })
  if (!res.ok) {
    throw new Error('Not authenticated')
  }
}

export async function list(): Promise<Token[]> {
  await checkAuth()
  const res = await fetch(`${BASE}/tokens`, { credentials: 'include' })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error || `Failed to list tokens (${res.status})`)
  }
  const data = await res.json()
  return data.tokens || []
}

export interface CreateResult {
  ok: boolean
  clientId: string
  clientSecret: string
}

export async function create(form: TokenForm): Promise<CreateResult> {
  await checkAuth()
  const res = await fetch(`${BASE}/tokens`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(form),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error || `Failed to create token (${res.status})`)
  }
  return res.json()
}

export async function revoke(clientID: string): Promise<void> {
  await checkAuth()
  const res = await fetch(`${BASE}/tokens/${clientID}`, {
    method: 'DELETE',
    credentials: 'include',
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error || `Failed to revoke token (${res.status})`)
  }
}
