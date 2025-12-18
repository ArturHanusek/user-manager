<template>
  <div class="auth-container">
    <div class="auth-card">
      <div v-if="loading" class="text-center">
        <div class="spinner" style="margin: 0 auto;"></div>
        <p style="margin-top: 1rem;">Loading...</p>
      </div>
      <div v-else>
        <p>Redirecting...</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';

const router = useRouter();
const loading = ref(true);

onMounted(async () => {
  try {
    const response = await fetch('/api/auth/status');
    const data = await response.json();

    if (data.needsSetup) {
      router.push('/setup');
    } else if (data.authenticated) {
      router.push('/dashboard');
    } else {
      router.push('/login');
    }
  } catch (error) {
    console.error('Failed to check auth status:', error);
    router.push('/login');
  } finally {
    loading.value = false;
  }
});
</script>
