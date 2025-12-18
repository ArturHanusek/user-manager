<template>
  <div class="container" style="padding-top: 2rem;">
    <header class="dashboard-header">
      <div class="user-info">
        <div class="user-avatar">{{ userInitial }}</div>
        <div>
          <strong>{{ user?.username }}</strong>
          <div style="font-size: 0.875rem; color: var(--gray-500);">{{ user?.email }}</div>
        </div>
      </div>
      <div style="display: flex; gap: 0.5rem;">
        <router-link v-if="user?.role === 'admin'" to="/admin" class="btn btn-primary">
          Admin Panel
        </router-link>
        <button @click="logout" class="btn" style="background: var(--gray-200);">
          Logout
        </button>
      </div>
    </header>

    <main>
      <h2 style="margin-bottom: 1rem;">Your Apps</h2>

      <div v-if="loading" style="text-align: center; padding: 2rem;">
        <div class="spinner" style="margin: 0 auto;"></div>
      </div>

      <div v-else-if="apps.length === 0" style="text-align: center; padding: 2rem; background: white; border-radius: 0.5rem;">
        <p style="color: var(--gray-500);">No apps deployed yet.</p>
        <button class="btn btn-primary" style="margin-top: 1rem;">Deploy New App</button>
      </div>

      <div v-else class="apps-grid">
        <div v-for="app in apps" :key="app.id" class="app-card">
          <h3>{{ app.app_type }}</h3>
          <span :class="'badge badge-' + getStatusColor(app.status)">
            {{ app.status }}
          </span>
          <p v-if="app.subdomain" style="margin-top: 0.5rem; font-size: 0.875rem;">
            {{ app.subdomain }}
          </p>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';

const router = useRouter();

const user = ref(null);
const apps = ref([]);
const loading = ref(true);

const userInitial = computed(() => {
  return user.value?.username?.charAt(0).toUpperCase() || '?';
});

function getStatusColor(status) {
  const colors = {
    running: 'success',
    stopped: 'warning',
    error: 'danger',
    pending: 'warning',
  };
  return colors[status] || 'warning';
}

async function fetchUser() {
  try {
    const response = await fetch('/api/auth/status');
    const data = await response.json();
    user.value = data.user;
  } catch (error) {
    console.error('Failed to fetch user:', error);
  }
}

async function fetchApps() {
  try {
    const response = await fetch('/api/user/apps');
    const data = await response.json();
    apps.value = data.apps || [];
  } catch (error) {
    console.error('Failed to fetch apps:', error);
  } finally {
    loading.value = false;
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
  } catch (error) {
    console.error('Logout failed:', error);
  }
}

onMounted(() => {
  fetchUser();
  fetchApps();
});
</script>

<style scoped>
.apps-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 1rem;
}

.app-card {
  background: white;
  padding: 1rem;
  border-radius: 0.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.app-card h3 {
  margin-bottom: 0.5rem;
}
</style>
