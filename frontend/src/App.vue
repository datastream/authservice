<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuth } from './composables/useAuth'

const route = useRoute()
const router = useRouter()
const { username, logout } = useAuth()

const isAuthPage = computed(() => {
  return route.path === '/login' || route.path === '/signup'
})
</script>

<template>
  <!-- Navigation bar for non-auth pages -->
  <nav v-if="!isAuthPage" class="nav">
    <div class="nav-inner">
      <router-link to="/tokens" class="nav-brand">Auth Server</router-link>
      <div class="nav-links">
        <router-link to="/tokens" class="nav-link">Token Manager</router-link>
        <span v-if="username" class="nav-user">{{ username }}</span>
        <button v-if="username" @click="handleLogout" class="nav-link nav-link-danger">Logout</button>
      </div>
    </div>
  </nav>

  <!-- Page content -->
  <main class="main">
    <router-view />
  </main>
</template>

<style scoped>
.nav {
  background: #fff;
  border-bottom: 1px solid #e5e7eb;
  padding: 0 24px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.nav-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  max-width: 1100px;
  margin: 0 auto;
}

.nav-brand {
  font-size: 1.25rem;
  font-weight: 700;
  color: #007bff;
  text-decoration: none;
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 16px;
}

.nav-link {
  color: #555;
  text-decoration: none;
  font-size: 0.9rem;
  transition: color 0.2s;
}

.nav-link:hover {
  color: #007bff;
}

.nav-link-danger {
  color: #dc3545;
}

.nav-link-danger:hover {
  color: #c82333;
}

.nav-user {
  color: #888;
  font-size: 0.85rem;
}

.main {
  min-height: calc(100vh - 56px);
}
</style>
