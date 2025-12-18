import { createRouter, createWebHistory } from 'vue-router';

const routes = [
  {
    path: '/',
    name: 'home',
    component: () => import('./views/HomeView.vue'),
  },
  {
    path: '/setup',
    name: 'setup',
    component: () => import('./views/SetupView.vue'),
    meta: { requiresNoAuth: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('./views/LoginView.vue'),
    meta: { requiresNoAuth: true },
  },
  {
    path: '/dashboard',
    name: 'dashboard',
    component: () => import('./views/DashboardView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/admin',
    name: 'admin',
    component: () => import('./views/AdminView.vue'),
    meta: { requiresAuth: true, requiresAdmin: true },
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

// Navigation guard
router.beforeEach(async (to, from, next) => {
  try {
    const response = await fetch('/api/auth/status');
    const data = await response.json();

    // If setup is needed, redirect to setup
    if (data.needsSetup && to.name !== 'setup') {
      return next({ name: 'setup' });
    }

    // If setup complete but not authenticated
    if (!data.needsSetup && !data.authenticated) {
      if (to.meta.requiresAuth) {
        return next({ name: 'login' });
      }
    }

    // If authenticated but trying to access auth pages
    if (data.authenticated && to.meta.requiresNoAuth) {
      return next({ name: 'dashboard' });
    }

    // Admin check
    if (to.meta.requiresAdmin && data.user?.role !== 'admin') {
      return next({ name: 'dashboard' });
    }

    next();
  } catch (error) {
    console.error('Auth check failed:', error);
    next();
  }
});

export default router;
