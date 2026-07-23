<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuth } from '@/composables/useAuth'
import * as tokenApi from '@/api/tokens'

const route = useRoute()
const router = useRouter()
const { checkSession } = useAuth()

const loading = ref(true)
const approving = ref(false)
const error = ref('')
const domain = ref('')

const clientId = route.query.client_id as string

// Build form data from query params for the approve endpoint
const formParams = computed(() => {
  const params = new URLSearchParams()
  params.set('client_id', clientId)
  if (route.query.redirect_uri) params.set('redirect_uri', route.query.redirect_uri as string)
  if (route.query.state) params.set('state', route.query.state as string)
  if (route.query.code_challenge) params.set('code_challenge', route.query.code_challenge as string)
  if (route.query.code_challenge_method) params.set('code_challenge_method', route.query.code_challenge_method as string)
  if (route.query.scope) params.set('scope', route.query.scope as string)
  return params
})

onMounted(async () => {
  try {
    const ok = await checkSession()
    if (!ok) {
      // Not authenticated — redirect to login with query params preserved
      error.value = 'Please log in to continue.'
      loading.value = false
      router.push({ name: 'Login', query: route.query })
      return
    }
    // Try to look up domain for display
    if (clientId) {
      try {
        const token = await tokenApi.getById(clientId)
        domain.value = token.domain || clientId
      } catch {
        domain.value = clientId
      }
    }
  } catch (e: any) {
    error.value = e.message || 'Failed to check session'
  } finally {
    loading.value = false
  }
})

async function handleApprove() {
  approving.value = true
  error.value = ''
  try {
    const res = await fetch('/oauth/authorize/approve', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formParams.value.toString(),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `Authorization failed (${res.status})`)
    }
    // The approve endpoint generates an auth code and returns a 302 redirect.
    // fetch doesn't follow it automatically, so we read the Location header.
    const location = res.headers.get('Location')
    if (location) {
      window.location.href = location
    } else {
      error.value = 'No redirect location returned by server.'
    }
  } catch (e: any) {
    error.value = e.message || 'Authorization failed'
  } finally {
    approving.value = false
  }
}
</script>

<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>Authorize</h1>
      <ErrorMessage :message="error" />
      <p v-if="domain" class="auth-text">
        Grant access to <strong>{{ domain }}</strong>?
      </p>
      <p v-else-if="!loading" class="auth-text">
        The client would like to log in.
      </p>
      <p v-else class="auth-text">Loading...</p>
      <form v-if="!loading && !error" @submit.prevent="handleApprove" class="auth-form">
        <input
          v-for="(value, key) in Object.fromEntries(formParams)"
          :key="key"
          type="hidden"
          :name="key"
          :value="value"
        />
        <button type="submit" class="btn btn-primary" :disabled="approving">
          {{ approving ? 'Approving...' : 'Allow' }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
.auth-page {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: calc(100vh - 56px);
  padding: 16px;
}

.auth-card {
  background: #fff;
  padding: 32px;
  border-radius: 10px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 400px;
  text-align: center;
}

.auth-card h1 {
  font-size: 1.75rem;
  margin-bottom: 20px;
  color: #333;
}

.auth-text {
  font-size: 1.05rem;
  color: #555;
  margin-bottom: 24px;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.btn {
  padding: 12px 20px;
  font-size: 1rem;
  font-weight: 600;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.btn-primary {
  background: #007bff;
  color: #fff;
}

.btn-primary:hover:not(:disabled) {
  background: #0056b3;
}
</style>