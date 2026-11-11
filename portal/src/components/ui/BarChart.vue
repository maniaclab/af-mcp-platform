<script setup lang="ts">
/**
 * BarChart.vue — a bar chart on Basecoat's chart component (`.chart`), which
 * wraps Chart.js. Both libraries are imported here, on first mount, so pages
 * without a chart do not load them. Chart.js is registered piece by piece
 * (a bar controller, its element and two scales, plus the tooltip plugin that
 * Basecoat's tooltip markup hooks into) rather than through `chart.js/auto`:
 * Basecoat's wrapper takes the `Chart` class in its config and registers
 * nothing itself.
 *
 * Colours are `var(--chart-N)` / `var(--border)` / `var(--muted-foreground)`
 * strings; Basecoat resolves them to computed colours when it creates the
 * chart and again, from the config it kept, when the `dark` class on `<html>`
 * changes, so no theme listener is needed here. The font family is read from
 * `--font-sans` for the same reason: Chart.js takes a family name, not a
 * `var()`.
 *
 * A canvas is opaque to assistive technology, so the chart is `role="img"`
 * with `ariaLabel` (also shown as a caption), and every value is repeated in a
 * visually hidden table beside it (outside the `role="img"` element, whose children are hidden).
 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';

const props = defineProps<{
  labels: string[];
  /** `plot: false` keeps a series in the hidden table without drawing it. */
  series: { label: string; values: number[]; plot?: boolean }[];
  ariaLabel: string;
  /** Formats values on the value axis and in the hidden table. */
  formatValue?: (value: number) => string;
}>();

interface ChartCanvas extends HTMLCanvasElement {
  _destroy?: () => void;
}

interface BasecoatChartApi {
  chart: (canvas: HTMLCanvasElement, config: object) => unknown;
}

const ANIMATION_MS = 200;
const FONT_SIZE = 12;

const canvas = ref<ChartCanvas | null>(null);
let unmounted = false;
let chartClass: typeof import('chart.js').Chart | null = null;

function format(value: number): string {
  return props.formatValue ? props.formatValue(value) : value.toLocaleString('en-US');
}

async function loadLibraries(): Promise<typeof import('chart.js').Chart> {
  if (chartClass) return chartClass;
  // Basecoat's script attaches `chart()` to `window.basecoat` when it runs and
  // exports nothing, so the namespace has to exist first.
  const win = window as unknown as { basecoat?: Partial<BasecoatChartApi> };
  win.basecoat ??= {};
  await import('basecoat-css/chart');
  // Named imports, not a namespace object: the bundler can only drop the
  // chart types this page does not use if it sees which ones are named.
  const { Chart, BarController, BarElement, CategoryScale, LinearScale, Tooltip } =
    await import('chart.js');
  Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip);
  chartClass = Chart;
  return Chart;
}

async function draw(): Promise<void> {
  const Chart = await loadLibraries();
  const el = canvas.value;
  if (unmounted || !el) return;

  const family = getComputedStyle(document.documentElement).getPropertyValue('--font-sans').trim();
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const tick = {
    color: 'var(--muted-foreground)',
    font: { family, size: FONT_SIZE },
  };

  const api = (window as unknown as { basecoat: BasecoatChartApi }).basecoat;
  api.chart(el, {
    Chart,
    type: 'bar',
    chartData: {
      labels: props.labels,
      datasets: props.series
        .filter((s) => s.plot !== false)
        .map((s, i) => ({
          label: s.label,
          data: s.values,
          backgroundColor: `var(--chart-${(i % 5) + 1})`,
          hoverBackgroundColor: 'var(--chart-2)',
          borderRadius: 0,
        })),
    },
    options: {
      animation: reducedMotion ? false : { duration: ANIMATION_MS },
      scales: {
        x: {
          grid: { display: false },
          ticks: { ...tick, padding: 8, autoSkip: true, maxRotation: 0 },
        },
        y: {
          beginAtZero: true,
          grid: { color: 'var(--border)' },
          ticks: {
            ...tick,
            maxTicksLimit: 4,
            callback: (value: number | string) => format(Number(value)),
          },
        },
      },
    },
  });
}

onMounted(draw);

watch(() => [props.labels, props.series], draw, { deep: true });

onBeforeUnmount(() => {
  unmounted = true;
  // Basecoat's own teardown: destroys the chart and removes its tooltip,
  // which it appends to <body>.
  canvas.value?._destroy?.();
});
</script>

<template>
  <figure class="bar-chart">
    <div class="chart" role="img" :aria-label="ariaLabel">
      <canvas ref="canvas"></canvas>
    </div>
    <figcaption class="bar-chart__caption">{{ ariaLabel }}</figcaption>
    <!-- The wrapper carries `sr-only`, not the table: Firefox lays a table's
         caption outside the table box that `sr-only` clips, so the caption of a
         `table.sr-only` stays visible. -->
    <div class="sr-only">
      <table>
        <caption>
          {{
            ariaLabel
          }}
        </caption>
        <thead>
          <tr>
            <th scope="col">Label</th>
            <th v-for="s in series" :key="s.label" scope="col">{{ s.label }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(label, i) in labels" :key="label">
            <th scope="row">{{ label }}</th>
            <td v-for="s in series" :key="s.label">{{ format(s.values[i]) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </figure>
</template>

<style scoped>
/* Basecoat's chart is 16:9, far too tall for a one-row strip of bars. */
.bar-chart .chart {
  aspect-ratio: auto;
  height: 200px;
}

.bar-chart__caption {
  margin-top: var(--space-8);
  font-size: var(--text-12);
  color: var(--color-af-text-secondary);
}
</style>
