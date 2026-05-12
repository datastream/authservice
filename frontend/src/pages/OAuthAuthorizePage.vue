<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuth } from '@/composables/useAuth'

const route = useRoute()
const { checkSession } = useAuth()

const loading = ref(true)
const error = ref('')
const domain = ref('')

const clientId = route.query.client_id as string

onMounted(async () => {
  // Check session - if not logged in, Go server's /oauth/authorize handler
  // will redirect to /login, so we just wait for it
  try {
    const ok = await checkSession()
    if (!ok) {
      // Not authenticated - let the Go server handle the session check
      // The Go handler at /oauth/authorize will redirect to /login
      loading.value = false
      return
    }
    // Try to look up domain for display
    if (clientId) {
      try {
        const res = await fetch(`/api/tokens/${clientId}`)
        if (res.ok) {
          const token = await res.json()
          domain.value = token.domain || clientId
        }
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
      <form v-if="!loading" action="/oauth/authorize" method="POST" class="auth-form">
        <!-- Preserve query parameters -->
        <input v-for="(value, key) in route.query" :key="key"
               type="hidden" :name="key" :value="value" />
        <button type="submit" class="btn btn-primary">Allow</button>
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
