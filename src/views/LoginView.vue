<template>
  <div class="auth-container">
    <div class="auth-card">
      <h1>Login</h1>

      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="lockoutMessage" class="alert alert-warning">{{ lockoutMessage }}</div>

      <!-- Step 1: Credentials -->
      <form v-if="!requiresTwoFactor" @submit.prevent="submitLogin">
        <div class="form-group">
          <label for="username">Username</label>
          <input
            id="username"
            v-model="form.username"
            name="username"
            type="text"
            placeholder="Enter username"
            required
            autocomplete="username"
          />
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="form.password"
            type="password"
            placeholder="Enter password"
            required
            autocomplete="current-password"
          />
        </div>

        <button type="submit" class="btn btn-primary btn-full" :disabled="loading || isLocked">
          {{ loading ? 'Logging in...' : 'Login' }}
        </button>
      </form>

      <!-- Step 2: 2FA Verification -->
      <form v-else @submit.prevent="submitTwoFactor">
        <p style="margin-bottom: 1rem; color: var(--gray-500); font-size: 0.875rem;">
          Enter the 6-digit code from your authenticator app
        </p>

        <div class="form-group">
          <label for="totpCode">Verification Code</label>
          <input
            id="totpCode"
            v-model="totpCode"
            type="text"
            placeholder="Enter 6-digit code"
            maxlength="6"
            pattern="[0-9]{6}"
            required
            autocomplete="one-time-code"
          />
        </div>

        <button type="submit" class="btn btn-primary btn-full" :disabled="loading">
          {{ loading ? 'Verifying...' : 'Verify' }}
        </button>

        <button
          type="button"
          class="btn btn-full"
          style="margin-top: 0.5rem;"
          @click="requiresTwoFactor = false"
        >
          Back to Login
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';

const router = useRouter();

const loading = ref(false);
const error = ref('');
const requiresTwoFactor = ref(false);
const lockoutUntil = ref(null);

const form = ref({
  username: '',
  password: '',
});

const totpCode = ref('');

const isLocked = computed(() => {
  if (!lockoutUntil.value) return false;
  return Date.now() < lockoutUntil.value;
});

const lockoutMessage = computed(() => {
  if (!isLocked.value) return '';
  const remaining = Math.ceil((lockoutUntil.value - Date.now()) / 60000);
  return `Account locked. Try again in ${remaining} minute(s).`;
});

async function submitLogin() {
  loading.value = true;
  error.value = '';

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: form.value.username,
        password: form.value.password,
      }),
    });

    const data = await response.json();

    if (response.status === 423) {
      lockoutUntil.value = data.lockedUntil;
      error.value = 'Account locked due to too many failed attempts';
      return;
    }

    if (!response.ok) {
      if (data.attemptsRemaining !== undefined) {
        error.value = `Invalid credentials. ${data.attemptsRemaining} attempts remaining.`;
      } else {
        error.value = data.error || 'Login failed';
      }
      return;
    }

    if (data.requiresTwoFactor) {
      requiresTwoFactor.value = true;
    } else if (data.success) {
      router.push('/dashboard');
    }
  } catch (err) {
    error.value = 'Network error. Please try again.';
  } finally {
    loading.value = false;
  }
}

async function submitTwoFactor() {
  loading.value = true;
  error.value = '';

  try {
    const response = await fetch('/api/auth/verify-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: totpCode.value,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Verification failed');
    }

    router.push('/dashboard');
  } catch (err) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
