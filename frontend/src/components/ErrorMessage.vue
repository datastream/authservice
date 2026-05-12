<script setup lang="ts">
interface Props {
  message?: string
}
defineProps<Props>()
</script>

<template>
  <div v-if="message" class="error-message">
    {{ message }}
  </div>
</template>

<style scoped>
.error-message {
  color: #dc3545;
  font-size: 0.875rem;
  margin-top: 0.5rem;
  padding: 0.5rem;
  background: #fff5f5;
  border: 1px solid #fed7d7;
  border-radius: 6px;
}
</style>
