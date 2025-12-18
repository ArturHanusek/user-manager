<template>
  <div class="container" style="padding-top: 2rem;">
    <header class="dashboard-header">
      <h1>Admin Panel</h1>
      <div style="display: flex; gap: 0.5rem;">
        <router-link to="/dashboard" class="btn" style="background: var(--gray-200);">
          Back to Dashboard
        </router-link>
      </div>
    </header>

    <main>
      <section style="margin-bottom: 2rem;">
        <h2 style="margin-bottom: 1rem;">Users</h2>

        <div v-if="loading" style="text-align: center; padding: 2rem;">
          <div class="spinner" style="margin: 0 auto;"></div>
        </div>

        <table v-else class="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in users" :key="user.id">
              <td>{{ user.id }}</td>
              <td>{{ user.username }}</td>
              <td>{{ user.email }}</td>
              <td>
                <span :class="'badge badge-' + (user.role === 'admin' ? 'success' : 'warning')">
                  {{ user.role }}
                </span>
              </td>
              <td>
                <span :class="'badge badge-' + (user.locked_until ? 'danger' : 'success')">
                  {{ user.locked_until ? 'Locked' : 'Active' }}
                </span>
              </td>
              <td>{{ formatDate(user.created_at) }}</td>
              <td>
                <button class="btn btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
                  Delete
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const users = ref([]);
const loading = ref(true);

function formatDate(timestamp) {
  if (!timestamp) return '-';
  return new Date(timestamp * 1000).toLocaleDateString();
}

async function fetchUsers() {
  try {
    const response = await fetch('/api/admin/users');
    const data = await response.json();
    users.value = data.users || [];
  } catch (error) {
    console.error('Failed to fetch users:', error);
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchUsers();
});
</script>
