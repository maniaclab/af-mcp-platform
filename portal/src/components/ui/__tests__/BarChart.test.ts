/**
 * Component tests for BarChart.vue. jsdom has no canvas, so Chart.js and
 * Basecoat's chart wrapper are replaced: the wrapper is the seam the component
 * talks to (`window.basecoat.chart(canvas, config)`), and a canvas it created a
 * chart for carries `_destroy`.
 */
import { flushPromises, mount } from '@vue/test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('chart.js', () => ({
  Chart: class {
    static register = vi.fn();
  },
  BarController: {},
  BarElement: {},
  CategoryScale: {},
  LinearScale: {},
  Tooltip: {},
}));
vi.mock('basecoat-css/chart', () => ({}));

import BarChart from '../BarChart.vue';

type Canvas = HTMLCanvasElement & { _destroy?: () => void };

const destroy = vi.fn();
const chartFn = vi.fn((canvas: Canvas, _config: object) => {
  canvas._destroy = destroy;
  return {};
});

const LABELS = ['2026-08-24', '2026-08-25', '2026-08-26'];
const SERIES = [{ label: 'Calls', values: [30, 0, 12] }];

function mountChart(props: Record<string, unknown> = {}) {
  return mount(BarChart, {
    props: { labels: LABELS, series: SERIES, ariaLabel: 'Calls per day', ...props },
    attachTo: document.body,
  });
}

function lastConfig() {
  return chartFn.mock.calls[chartFn.mock.calls.length - 1][1] as {
    Chart: unknown;
    type: string;
    chartData: { labels: string[]; datasets: { label: string; data: number[] }[] };
    options: {
      animation: boolean | object;
      scales: { y: { ticks: { callback: (v: number) => string } } };
    };
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  (window as unknown as { basecoat: unknown }).basecoat = { chart: chartFn };
  window.matchMedia = vi.fn().mockReturnValue({ matches: false }) as typeof window.matchMedia;
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('BarChart', () => {
  it('creates a bar chart from the labels and series', async () => {
    mountChart();
    await flushPromises();

    expect(chartFn).toHaveBeenCalledTimes(1);
    const config = lastConfig();
    expect(config.type).toBe('bar');
    expect(config.chartData.labels).toEqual(LABELS);
    expect(config.chartData.datasets).toHaveLength(1);
    expect(config.chartData.datasets[0].label).toBe('Calls');
    expect(config.chartData.datasets[0].data).toEqual([30, 0, 12]);
  });

  it('renders Basecoat chart markup that is an image with the given name', async () => {
    const wrapper = mountChart();
    await flushPromises();

    const chart = wrapper.find('.chart');
    expect(chart.attributes('role')).toBe('img');
    expect(chart.attributes('aria-label')).toBe('Calls per day');
    expect(chart.find('canvas').exists()).toBe(true);
  });

  it('keeps every value available as text in a visually hidden table', async () => {
    const wrapper = mountChart();
    await flushPromises();

    const table = wrapper.find('.sr-only table');
    expect(table.exists()).toBe(true);
    // The data is not inside the role="img" element, which hides its children.
    expect(wrapper.find('.chart table').exists()).toBe(false);
    expect(table.find('caption').text()).toBe('Calls per day');
    const rows = table.findAll('tbody tr');
    expect(rows).toHaveLength(3);
    expect(rows[0].text()).toContain('2026-08-24');
    expect(rows[0].text()).toContain('30');
    expect(rows[1].text()).toContain('0');
  });

  it('hides the table with a wrapper, never on the table itself', async () => {
    const wrapper = mountChart();
    await flushPromises();

    // Firefox draws a table's caption outside the table box that `sr-only`
    // clips, so a caption inside `table.sr-only` shows as stray visible text.
    expect(wrapper.find('table.sr-only').exists()).toBe(false);
    expect(wrapper.find('.sr-only table caption').exists()).toBe(true);
  });

  it('shows the chart summary as a visible caption, not as hidden text', async () => {
    const wrapper = mountChart();
    await flushPromises();

    const caption = wrapper.get('figure > figcaption');
    expect(caption.text()).toBe('Calls per day');
    expect(caption.classes()).not.toContain('sr-only');
    expect(caption.element.closest('.sr-only')).toBeNull();
  });

  it('lists a series marked as not drawn in the table only', async () => {
    const wrapper = mountChart({
      series: [...SERIES, { label: 'Tokens', values: [11, 0, 4], plot: false }],
    });
    await flushPromises();

    expect(lastConfig().chartData.datasets.map((d) => d.label)).toEqual(['Calls']);
    expect(wrapper.findAll('thead th').map((th) => th.text())).toEqual([
      'Label',
      'Calls',
      'Tokens',
    ]);
    expect(wrapper.findAll('tbody tr')[0].text()).toContain('11');
  });

  it('formats the hidden table and the axis with the value formatter', async () => {
    const wrapper = mountChart({ formatValue: (n: number) => `${n} calls` });
    await flushPromises();

    expect(wrapper.findAll('tbody tr')[0].text()).toContain('30 calls');
    expect(lastConfig().options.scales.y.ticks.callback(5)).toBe('5 calls');
  });

  it('draws again when the props change', async () => {
    const wrapper = mountChart();
    await flushPromises();

    await wrapper.setProps({
      labels: ['a', 'b'],
      series: [{ label: 'Calls', values: [1, 2] }],
    });
    await flushPromises();

    expect(chartFn).toHaveBeenCalledTimes(2);
    expect(lastConfig().chartData.labels).toEqual(['a', 'b']);
    expect(wrapper.findAll('tbody tr')).toHaveLength(2);
  });

  it('destroys the chart on unmount', async () => {
    const wrapper = mountChart();
    await flushPromises();

    wrapper.unmount();
    expect(destroy).toHaveBeenCalledTimes(1);
  });

  it('does not draw after being unmounted before the libraries load', async () => {
    const wrapper = mountChart();
    wrapper.unmount();
    await flushPromises();

    expect(chartFn).not.toHaveBeenCalled();
  });

  it('turns animation off when the visitor prefers reduced motion', async () => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: true }) as typeof window.matchMedia;
    mountChart();
    await flushPromises();

    expect(lastConfig().options.animation).toBe(false);
  });
});
