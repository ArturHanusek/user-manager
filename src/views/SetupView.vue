<template>
  <div class="auth-container">
    <div class="auth-card">
      <!-- Step 1: Account Details -->
      <div v-if="step === 1">
        <h1>Create Account</h1>

        <div v-if="error" class="alert alert-error">{{ error }}</div>

        <form @submit.prevent="submitDetails">
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
            <label for="email">Email</label>
            <input
              id="email"
              v-model="form.email"
              name="email"
              type="email"
              placeholder="Enter email"
              required
              autocomplete="email"
            />
          </div>

          <div class="form-group">
            <label for="password">Password</label>
            <input
              id="password"
              v-model="form.password"
              name="password"
              type="password"
              placeholder="Enter password"
              required
              autocomplete="new-password"
              @focus="showRequirements = true"
            />
            <div v-if="showRequirements" class="password-requirements">
              <ul>
                <li :class="{ valid: passwordChecks.length }">
                  {{ passwordChecks.length ? '✓' : '○' }} At least 12 characters
                </li>
                <li :class="{ valid: passwordChecks.lowercase }">
                  {{ passwordChecks.lowercase ? '✓' : '○' }} Lowercase letter
                </li>
                <li :class="{ valid: passwordChecks.uppercase }">
                  {{ passwordChecks.uppercase ? '✓' : '○' }} Uppercase letter
                </li>
                <li :class="{ valid: passwordChecks.number }">
                  {{ passwordChecks.number ? '✓' : '○' }} Number
                </li>
                <li :class="{ valid: passwordChecks.special }">
                  {{ passwordChecks.special ? '✓' : '○' }} Special character
                </li>
              </ul>
            </div>
          </div>

          <div class="form-group">
            <label for="confirmPassword">Confirm Password</label>
            <input
              id="confirmPassword"
              v-model="form.confirmPassword"
              type="password"
              placeholder="Confirm password"
              required
              autocomplete="new-password"
            />
          </div>

          <button type="submit" class="btn btn-primary btn-full" :disabled="loading || !isPasswordValid">
            {{ loading ? 'Creating...' : 'Continue' }}
          </button>
        </form>
      </div>

      <!-- Step 2: 2FA Setup -->
      <div v-else-if="step === 2">
        <h1>Setup Two-Factor Auth</h1>

        <div v-if="error" class="alert alert-error">{{ error }}</div>

        <p style="margin-bottom: 1rem; color: var(--gray-500); font-size: 0.875rem;">
          Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
        </p>

        <div class="qr-container">
          <img :src="qrCode" alt="QR Code" data-testid="qr-code" />
          <p class="secret-code">{{ secret }}</p>
        </div>

        <form @submit.prevent="verifyTotp">
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
            {{ loading ? 'Verifying...' : 'Verify & Complete' }}
          </button>
        </form>
      </div>

      <!-- Step 3: Backup Codes -->
      <div v-else-if="step === 3">
        <h1>Save Backup Codes</h1>

        <div class="alert alert-warning">
          Save these codes in a safe place. You can use them to access your account if you lose your authenticator.
        </div>

        <div class="backup-codes">
          <div v-for="code in backupCodes" :key="code" class="backup-code">
            {{ code }}
          </div>
        </div>

        <button @click="completeSetup" class="btn btn-primary btn-full">
          I've saved my codes - Continue
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';

const router = useRouter();

const step = ref(1);
const loading = ref(false);
const error = ref('');
const showRequirements = ref(false);

const form = ref({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
});

const qrCode = ref('');
const secret = ref('');
const totpCode = ref('');
const backupCodes = ref([]);

const passwordChecks = computed(() => ({
  length: form.value.password.length >= 12,
  lowercase: /[a-z]/.test(form.value.password),
  uppercase: /[A-Z]/.test(form.value.password),
  number: /[0-9]/.test(form.value.password),
  special: /[!@#$%^&*()_+\-=\[\]{}';:"\\|,.<>\/?]/.test(form.value.password),
}));

const isPasswordValid = computed(() =>
  Object.values(passwordChecks.value).every(Boolean) &&
  form.value.password === form.value.confirmPassword
);

async function submitDetails() {
  if (!isPasswordValid.value) {
    error.value = 'Please meet all password requirements';
    return;
  }

  loading.value = true;
  error.value = '';

  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: form.value.username,
        email: form.value.email,
        password: form.value.password,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Registration failed');
    }

    qrCode.value = data.qrCode;
    secret.value = data.secret;
    step.value = 2;
  } catch (err) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function verifyTotp() {
  loading.value = true;
  error.value = '';

  try {
    const response = await fetch('/api/auth/register/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: form.value.username,
        totpCode: totpCode.value,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Verification failed');
    }

    backupCodes.value = data.backupCodes;
    step.value = 3;
  } catch (err) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function completeSetup() {
  router.push('/dashboard');
}
</script>
