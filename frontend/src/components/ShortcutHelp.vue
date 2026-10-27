<script setup lang="ts">
// 快捷键说明浮层。
//
// 为什么值得有一层浮面：键盘快捷键是"知道才会用"的功能，写在 README 里等于
// 只对读过 README 的人存在。浮层让顶栏那一个小按钮就能把整套键位摊开，
// 也让"这层能不能用键盘关掉"这件事有一个明确的 answers。
import { onMounted, ref } from 'vue'

const props = defineProps<{ keys: Array<{ combo: string; what: string }> }>()
const emit = defineEmits<{ (e: 'close'): void }>()

const closeBtn = ref<HTMLElement | null>(null)

onMounted(() => {
  // 打开就夺走焦点：否则第二次按键会落在浮层后面的控件上，
  // 用户以为在读说明，实际已经把某个开关拨动了。
  closeBtn.value?.focus()
})
</script>

<template>
  <div class="scrim" @click.self="emit('close')">
    <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="kbd-title">
      <h3 id="kbd-title">键盘快捷键</h3>
      <dl>
        <template v-for="k in props.keys" :key="k.combo">
          <dt><kbd>{{ k.combo }}</kbd></dt>
          <dd>{{ k.what }}</dd>
        </template>
      </dl>
      <p class="note">
        启动/停止代理、切模式、切节点这些<strong>会改变流量去向</strong>的动作没有快捷键：
        一个键就能把整机改道，而误按的那一下不会自己解释。它们只在按得到的按钮上。
      </p>
      <button ref="closeBtn" type="button" class="btn" @click="emit('close')">关闭（Esc）</button>
    </div>
  </div>
</template>

<style scoped>
.scrim {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--sp-6);
  background: rgba(4, 6, 10, 0.62);
  backdrop-filter: blur(3px);
}

.sheet {
  width: min(460px, 100%);
  max-height: 80vh;
  overflow: auto;
  padding: var(--sp-5);
  border: 1px solid var(--line-2);
  border-radius: var(--r-lg);
  background: var(--surface-2);
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
}

.sheet h3 {
  margin: 0 0 var(--sp-3);
  font-size: var(--fs-title);
  font-weight: 600;
  letter-spacing: -0.015em;
}

dl {
  margin: 0 0 var(--sp-3);
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--sp-2) var(--sp-3);
  align-items: baseline;
}

dt kbd {
  padding: 2px 7px;
  border: 1px solid var(--line-3);
  border-radius: var(--r-xs);
  background: var(--surface-3);
  font-family: var(--mono);
  font-size: var(--fs-caption);
  white-space: nowrap;
}

dd {
  margin: 0;
  color: var(--fg-2);
  font-size: var(--fs-sm);
}

.note {
  margin: 0 0 var(--sp-4);
  padding: var(--sp-2) var(--sp-3);
  border-left: 2px solid var(--warn-line);
  background: var(--surface-3);
  border-radius: 0 var(--r-sm) var(--r-sm) 0;
  color: var(--muted);
  font-size: var(--fs-caption);
  line-height: 1.6;
}

.note strong {
  color: var(--fg-2);
  font-weight: 600;
}
</style>
