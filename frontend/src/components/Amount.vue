<script setup lang="ts">
// Amount 把「10.4 MB/s」这种串画成大数字 + 小单位。
//
// 单独一个组件是因为统计块有好几处用它，各自写模板的话，
// 字号与对齐迟早会在某次改动里走散。
import { computed } from 'vue'
import { splitAmount } from '../format'

const props = defineProps<{ text: string }>()

const parts = computed(() => splitAmount(props.text))
</script>

<template>
  <span class="amount"
    ><span class="v">{{ parts.value }}</span
    ><span v-if="parts.unit" class="u">{{ parts.unit }}</span></span
  >
</template>

<style scoped>
/* 数字与单位同一条基线，单位只是小一档的跟随者，不许换行。 */
.amount {
  display: inline-flex;
  align-items: baseline;
  white-space: nowrap;
}

.u {
  margin-left: 3px;
  font-size: 0.46em;
  font-weight: 500;
  letter-spacing: 0;
  color: var(--muted);
}
</style>
