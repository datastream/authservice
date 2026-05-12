import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuth } from '@/composables/useAuth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/pages/LoginPage.vue'),
  },
  {
    path: '/signup',
    name: 'Signup',
    component: () => import('@/pages/SignupPage.vue'),
  },
  {
    path: '/tokens',
    name: 'TokenManager',
    component: () => import('@/pages/TokenManagerPage.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/oauth/authorize',
    name: 'OAuthAuthorize',
    component: () => import('@/pages/OAuthAuthorizePage.vue'),
  },
  {
    path: '/',
    redirect: '/tokens',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Navigation guard: redirect unauthenticated users to login
router.beforeEach(async (to) => {
  if (to.meta.requiresAuth) {
    const { checkSession } = useAuth()
    const ok = await checkSession()
    if (!ok) {
      return { name: 'Login', query: to.query }
    }
  }
})

export default router
