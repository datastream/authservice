<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuth } from '@/composables/useAuth'
import * as tokenApi from '@/api/tokens'
import type { Token } from '@/api/tokens'
import ErrorMessage from '@/components/ErrorMessage.vue'

const { logout, checkSession } = useAuth()

const tokens = ref<Token[]>([])
const loading = ref(true)
const creating = ref(false)
const error = ref('')
const success = ref('')

const newDomain = ref('')
const newPublic = ref(false)
const newDescribe = ref('')
const newUser = ref('')

const validateForm = () => {
  if (!newDomain.value.trim()) {
    error.value = 'Domain is required'
    return false
  }
  return true
}

const fetchTokens = async () => {
  try {
    tokens.value = await tokenApi.list()
  } catch (e: any) {
    error.value = e.message || 'Failed to fetch tokens'
  } finally {
    loading.value = false
  }
}

const handleCreate = async () => {
  error.value = ''
  success.value = ''
  if (!validateForm()) return
  creating.value = true
  try {
    const body: tokenApi.TokenForm = {
      domain: newDomain.value,
      public: newPublic.value,
      describe: newDescribe.value || undefined,
    }
    if (newUser.value.trim()) {
      body.userId = newUser.value
    }
    const result = await tokenApi.create(body)
    success.value = `Token created: ${result.clientId}`
    newDomain.value = ''
    newPublic.value = false
    newDescribe.value = ''
    newUser.value = ''
    await fetchTokens()
  } catch (e: any) {
    error.value = e.message || 'Failed to create token'
  } finally {
    creating.value = false
  }
}

const handleRevoke = async (clientID: string) => {
  if (!confirm('Revoke this token?')) return
  error.value = ''
  success.value = ''
  try {
    await tokenApi.revoke(clientID)
    success.value = 'Token revoked'
    await fetchTokens()
  } catch (e: any) {
    error.value = e.message || 'Failed to revoke token'
  }
}

onMounted(fetchTokens)
</script>

<template>
  <div class="token-manager">
    <div class="token-manager__panel">
      <h2>Create Token</h2>
      <ErrorMessage :message="error" />
      <div v-if="success" class="success-message">{{ success }}</div>

      <form @submit.prevent="handleCreate" class="token-form">
        <div class="form-group">
          <label for="domain">Domain</label>
          <input
            id="domain"
            v-model="newDomain"
            type="text"
            placeholder="Enter the domain"
            required
          />
        </div>

        <div class="form-group">
          <label for="public">Client Type</label>
          <select id="public" v-model="newPublic">
            <option :value="false">Private</option>
            <option :value="true">Public</option>
          </select>
        </div>

        <div class="form-group">
          <label for="describe">Description</label>
          <textarea
            id="describe"
            v-model="newDescribe"
            rows="3"
            placeholder="Enter description (optional)"
          ></textarea>
        </div>

        <div class="form-group">
          <label for="userId">User ID</label>
          <input
            id="userId"
            v-model="newUser"
            type="text"
            placeholder="Leave empty for your own user (optional)"
          />
        </div>

        <button type="submit" class="btn btn-primary" :disabled="creating">
          {{ creating ? 'Creating...' : 'Create Token' }}
        </button>
      </form>
    </div>

    <div class="token-manager__panel">
      <h2>Existing Tokens</h2>
      <div v-if="loading" class="loading">Loading tokens...</div>
      <div v-else-if="tokens.length === 0" class="empty">No tokens yet.</div>
      <ul v-else class="token-list">
        <li v-for="token in tokens" :key="token.clientID" class="token-item">
          <div class="token-info">
            <strong>{{ token.domain }}</strong>
            <span class="token-badge" :class="{ 'token-badge--public': token.public }">
              {{ token.public ? 'Public' : 'Private' }}
            </span>
          </div>
          <div class="token-details">
            <p><strong>Client ID:</strong> {{ token.clientID }}</p>
            <p><strong>Client Secret:</strong> {{ token.clientSecret }}</p>
            <p v-if="token.describe"><strong>Description:</strong> {{ token.describe }}</p>
          </div>
          <button
            class="btn btn-danger btn-sm"
            @click="handleRevoke(token.clientID)"
          >
            Revoke
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.token-manager {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  width: 100%;
  max-width: 1100px;
  margin: 0 auto;
}

@media (max-width: 768px) {
  .token-manager {
    grid-template-columns: 1fr;
  }
}

.token-manager__panel {
  background: #fff;
  padding: 24px;
  border-radius: 10px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.token-manager__panel h2 {
  font-size: 1.25rem;
  margin-bottom: 16px;
  color: #333;
}

.token-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.form-group {
  text-align: left;
}

.form-group label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #555;
  margin-bottom: 4px;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 10px 12px;
  font-size: 1rem;
  border: 1px solid #ccc;
  border-radius: 6px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  border-color: #007bff;
  box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
}

.btn {
  padding: 10px 16px;
  font-size: 0.95rem;
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

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-danger {
  background: #dc3545;
  color: #fff;
}

.btn-danger:hover {
  background: #c82333;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 0.85rem;
}

.loading {
  color: #888;
  text-align: center;
  padding: 20px;
}

.empty {
  color: #888;
  text-align: center;
  padding: 20px;
}

.success-message {
  color: #28a745;
  font-size: 0.875rem;
  margin-bottom: 8px;
  padding: 8px;
  background: #f0fff4;
  border: 1px solid #c3e6cb;
  border-radius: 6px;
}

.token-list {
  list-style: none;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.token-item {
  background: #f8f9fa;
  padding: 16px;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.token-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.token-badge {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 12px;
  background: #e9ecef;
  color: #555;
}

.token-badge--public {
  background: #fff3cd;
  color: #856404;
}

.token-details p {
  font-size: 0.85rem;
  color: #555;
  margin: 2px 0;
}

.token-item button {
  align-self: flex-end;
}
</style>
