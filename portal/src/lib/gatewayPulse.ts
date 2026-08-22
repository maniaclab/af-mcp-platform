/**
 * gatewayPulse.ts — the public landing page's one explanatory motion moment
 * for the "how it works" diagram: a small light travels AI Assistant -> MCP
 * Gateway -> a backend (Rucio), lighting up each box in turn, preceded by a
 * "user" / "tool call" exchange near the AI Assistant node. Purely
 * illustrative (every element it touches is aria-hidden) -- the diagram's
 * own labels already carry the real content; this just makes the request
 * flow legible at a glance.
 *
 * Gated the same way as the Overview hero's particle-track canvas: skipped
 * entirely under prefers-reduced-motion (this loop is decoration on top of
 * an already-complete static diagram, not feedback for a user action, so
 * "off" is a fully legible fallback), and played only while the diagram is
 * actually on screen via ScrollTrigger, per the "any nonessential loop must
 * stop when offscreen" rule.
 */
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

const ACTIVE_CLASS = 'is-pulse-active';

// Every position below is read fresh (via these functions, called from
// GSAP's function-based tween values) at the moment each tween starts --
// including every `repeat` iteration -- so a resize between loops is
// picked up automatically without a separate resize listener.
function centerX(el: Element, containerRect: DOMRect): number {
  const r = el.getBoundingClientRect();
  return r.left + r.width / 2 - containerRect.left;
}

function topY(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().top - containerRect.top;
}

function bottomY(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().bottom - containerRect.top;
}

/**
 * Wires up the pulse loop for the `.diagram` element inside `root` (the
 * page passes its `.diagram` container). Returns a cleanup function; a
 * no-op cleanup is returned (and nothing is animated) if reduced motion is
 * preferred or any expected node is missing from the DOM.
 */
export function initGatewayPulse(root: HTMLElement): () => void {
  if (!window.matchMedia('(prefers-reduced-motion: no-preference)').matches) {
    return () => {};
  }

  const client = root.querySelector<HTMLElement>('[data-pulse-node="client"]');
  const gateway = root.querySelector<HTMLElement>('[data-pulse-node="gateway"]');
  const rucio = root.querySelector<HTMLElement>('[data-pulse-node="rucio"]');
  const fanout = root.querySelector<HTMLElement>('.diagram__fanout');
  const dot = root.querySelector<HTMLElement>('[data-pulse-dot]');
  const userCallout = root.querySelector<HTMLElement>('[data-pulse-callout="user"]');
  const toolCallout = root.querySelector<HTMLElement>('[data-pulse-callout="tool"]');

  if (!client || !gateway || !rucio || !fanout || !dot || !userCallout || !toolCallout) {
    return () => {};
  }

  const rect = () => root.getBoundingClientRect();
  const calloutX = () => centerX(client, rect()) + client.offsetWidth / 2 + 16;

  const tl = gsap.timeline({ repeat: -1, repeatDelay: 1.2, paused: true });

  // "user: find me a dataset" -> "tool call: rucio_list_dataset", both
  // anchored beside the AI Assistant box -- the tool call is the assistant
  // deciding to act; the pulse below is that call actually reaching the
  // gateway and the backend.
  tl.set([userCallout, toolCallout], { x: calloutX, y: () => topY(client, rect()) })
    .to(userCallout, { opacity: 1, duration: 0.3, ease: 'power2.out' })
    .to(userCallout, { opacity: 0, duration: 0.25, ease: 'power2.in' }, '+=0.8')
    .to(toolCallout, { opacity: 1, duration: 0.25, ease: 'power2.out' }, '<')
    .to(toolCallout, { opacity: 0, duration: 0.25, ease: 'power2.in' }, '+=0.8')
    .call(() => client.classList.add(ACTIVE_CLASS))
    .set(dot, { x: () => centerX(client, rect()), y: () => bottomY(client, rect()) })
    .to(dot, { opacity: 1, duration: 0.2 })
    .to(dot, { y: () => topY(gateway, rect()), duration: 0.6, ease: 'power1.inOut' })
    .call(() => {
      client.classList.remove(ACTIVE_CLASS);
      gateway.classList.add(ACTIVE_CLASS);
    })
    .to(dot, { y: () => topY(fanout, rect()), duration: 0.35, ease: 'power1.inOut' }, '+=0.2')
    .to(dot, { x: () => centerX(rucio, rect()), duration: 0.45, ease: 'power1.inOut' })
    .to(dot, { y: () => topY(rucio, rect()), duration: 0.35, ease: 'power1.inOut' })
    .call(() => {
      gateway.classList.remove(ACTIVE_CLASS);
      rucio.classList.add(ACTIVE_CLASS);
    })
    .to(dot, { opacity: 0, duration: 0.4, ease: 'power2.in' }, '+=0.6')
    .call(() => rucio.classList.remove(ACTIVE_CLASS));

  const trigger = ScrollTrigger.create({
    trigger: root,
    start: 'top 85%',
    end: 'bottom 15%',
    onEnter: () => tl.play(),
    onEnterBack: () => tl.play(),
    onLeave: () => tl.pause(),
    onLeaveBack: () => tl.pause(),
  });

  return function cleanup(): void {
    tl.kill();
    trigger.kill();
  };
}
