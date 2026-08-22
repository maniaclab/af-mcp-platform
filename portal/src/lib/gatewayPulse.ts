/**
 * gatewayPulse.ts — the public landing page's one explanatory motion moment
 * for the "how it works" diagram. A small light travels AI Assistant -> MCP
 * Gateway -> a backend, lighting up boxes and gateway checks as it passes,
 * alongside a small growing "chat log" beside the AI Assistant box. Three
 * scripted cycles run back to back and then repeat: two successful calls
 * (Rucio, HTCondor) and one denied at policy. Purely illustrative (every
 * element it touches is aria-hidden) -- the diagram's own labels already
 * carry the real content; this just makes the request flow legible.
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
const DENIED_CLASS = 'is-pulse-denied';

type TagState = '' | 'checking' | 'ok' | 'fail';
type TagKey = 'auth' | 'policy' | 'audit' | 'broker';
type TargetKey = 'rucio' | 'htcondor';

interface Cycle {
  userText: string;
  aiCallText: string;
  aiResultText: string;
  tagOutcomes: Record<'auth' | 'policy' | 'audit', TagState>;
  credentialLabel: string | null;
  target: TargetKey | null;
}

const CYCLES: Cycle[] = [
  {
    userText: 'find me a dataset',
    aiCallText: 'tool_call(rucio_list_dsids)',
    aiResultText: 'Found 3 datasets...',
    tagOutcomes: { auth: 'ok', policy: 'ok', audit: 'ok' },
    credentialLabel: 'x509',
    target: 'rucio',
  },
  {
    userText: 'launch a batch job',
    aiCallText: 'tool_call(condor_submit_job)',
    aiResultText: 'Launched job 293813.0',
    tagOutcomes: { auth: 'ok', policy: 'ok', audit: 'ok' },
    credentialLabel: 'condor-token',
    target: 'htcondor',
  },
  {
    userText: 'Delete my /data datasets',
    aiCallText: 'tool_call(fs_delete_dir)',
    aiResultText: 'I am not authorized...',
    tagOutcomes: { auth: 'ok', policy: 'fail', audit: 'fail' },
    credentialLabel: null,
    target: null,
  },
];

// Timing constants (seconds) -- named so the sequence below reads as a
// storyboard rather than a wall of magic numbers.
const TIME = {
  chatReveal: 0.3,
  chatHoldShort: 0.55,
  chatHoldLong: 0.7,
  chatHoldFinal: 1.9,
  chatCollapse: 0.4,
  dotFade: 0.15,
  travelShort: 0.3,
  travelMed: 0.4,
  travelLong: 0.55,
  tagCheck: 0.22,
  tagResolveHold: 0.18,
  creditHold: 0.35,
  arrivalHold: 0.45,
  // Long enough for the DENIED_CLASS's 3x160ms CSS buzz animation
  // (index.astro's diagram-denied-buzz keyframe) to finish playing before
  // the class is removed and the pulse starts back toward the AI
  // Assistant box.
  deniedGap: 0.55,
};

// Every position below is read fresh (via these, called from GSAP's
// function-based tween values) at the moment each tween starts -- including
// every `repeat` iteration -- so a resize between loops is picked up
// automatically without a separate resize listener.
function centerX(el: Element, containerRect: DOMRect): number {
  const r = el.getBoundingClientRect();
  return r.left + r.width / 2 - containerRect.left;
}

function centerY(el: Element, containerRect: DOMRect): number {
  const r = el.getBoundingClientRect();
  return r.top + r.height / 2 - containerRect.top;
}

function topY(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().top - containerRect.top;
}

function bottomY(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().bottom - containerRect.top;
}

function leftX(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().left - containerRect.left;
}

function setTagState(el: HTMLElement, state: TagState): void {
  if (state) {
    el.dataset.state = state;
  } else {
    delete el.dataset.state;
  }
}

interface ChatLine {
  wrapper: HTMLElement;
  text: HTMLElement;
}

interface Refs {
  root: HTMLElement;
  client: HTMLElement;
  gateway: HTMLElement;
  fanout: HTMLElement;
  credential: HTMLElement;
  credentialLabel: HTMLElement;
  dot: HTMLElement;
  tags: Record<TagKey, HTMLElement>;
  leaves: Record<TargetKey, HTMLElement>;
  chatLines: [ChatLine, ChatLine, ChatLine];
}

function resolveRefs(root: HTMLElement): Refs | null {
  const client = root.querySelector<HTMLElement>('[data-pulse-node="client"]');
  const gateway = root.querySelector<HTMLElement>('[data-pulse-node="gateway"]');
  const fanout = root.querySelector<HTMLElement>('.diagram__fanout');
  const credential = root.querySelector<HTMLElement>('[data-pulse-node="credential"]');
  const credentialLabel = root.querySelector<HTMLElement>('[data-credential-label]');
  const dot = root.querySelector<HTMLElement>('[data-pulse-dot]');
  const rucio = root.querySelector<HTMLElement>('[data-pulse-node="rucio"]');
  const htcondor = root.querySelector<HTMLElement>('[data-pulse-node="htcondor"]');

  const tagKeys: TagKey[] = ['auth', 'policy', 'audit', 'broker'];
  const tags = {} as Record<TagKey, HTMLElement>;
  for (const key of tagKeys) {
    const el = root.querySelector<HTMLElement>(`[data-gateway-tag="${key}"]`);
    if (!el) return null;
    tags[key] = el;
  }

  const chatLineEls = root.querySelectorAll<HTMLElement>('[data-chat-line]');
  if (chatLineEls.length !== 3) return null;
  const chatLines = Array.from(chatLineEls).map((wrapper) => {
    const text = wrapper.querySelector<HTMLElement>('[data-chat-text]');
    return text ? { wrapper, text } : null;
  });
  if (chatLines.some((l) => l === null)) return null;

  if (
    !client ||
    !gateway ||
    !fanout ||
    !credential ||
    !credentialLabel ||
    !dot ||
    !rucio ||
    !htcondor
  ) {
    return null;
  }

  return {
    root,
    client,
    gateway,
    fanout,
    credential,
    credentialLabel,
    dot,
    tags,
    leaves: { rucio, htcondor },
    chatLines: chatLines as [ChatLine, ChatLine, ChatLine],
  };
}

/** Builds one cycle's fully-scripted timeline. Every position is a function
 * re-evaluated at play time, so this is safe to build once and let a parent
 * timeline repeat indefinitely. */
function buildCycleTimeline(cycle: Cycle, refs: Refs): gsap.core.Timeline {
  const tl = gsap.timeline();
  const rect = () => refs.root.getBoundingClientRect();
  const { client, gateway, fanout, credential, credentialLabel, dot, tags, chatLines } = refs;
  let t = 0;

  // -- chat: user's request --
  // Text is set inside a .call() rather than assigned directly here --
  // buildCycleTimeline() runs for all three cycles up front (see the
  // `for` loop below), and the three cycles share the same DOM elements,
  // so a direct assignment here would have the last cycle built silently
  // overwrite the first two before anything ever plays.
  tl.call(() => (chatLines[0].text.textContent = cycle.userText), undefined, t);
  tl.to(
    chatLines[0].wrapper,
    { height: 'auto', opacity: 1, duration: TIME.chatReveal, ease: 'power2.out' },
    t,
  );
  t += TIME.chatReveal + TIME.chatHoldShort;

  // -- a small dot carries the request from the chat log to the AI
  // Assistant box, which then "thinks" (spinner) before it decides on a
  // tool call -- a beat between the user's message landing and the
  // assistant's response appearing. --
  tl.call(
    () =>
      gsap.set(dot, {
        x: () => leftX(chatLines[0].wrapper, rect()),
        y: () => centerY(chatLines[0].wrapper, rect()),
      }),
    undefined,
    t,
  );
  tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
  t += TIME.dotFade;
  tl.to(
    dot,
    {
      x: () => centerX(client, rect()),
      y: () => centerY(client, rect()),
      duration: TIME.travelMed,
      ease: 'power1.inOut',
    },
    t,
  );
  t += TIME.travelMed;
  tl.call(
    () => {
      client.classList.add(ACTIVE_CLASS);
      setTagState(client, 'checking');
    },
    undefined,
    t,
  );
  tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
  // Both the spinner and the border glow deliberately keep going past this
  // point -- the box is still "occupied" while the assistant is deciding
  // what to do (through the tool_call line below), and only clear once the
  // pulse actually departs toward the gateway, later on.
  t += TIME.dotFade + 0.55 + 0.25;

  // -- chat: the assistant's resulting tool call --
  tl.call(() => (chatLines[1].text.textContent = cycle.aiCallText), undefined, t);
  tl.to(
    chatLines[1].wrapper,
    { height: 'auto', opacity: 1, duration: TIME.chatReveal, ease: 'power2.out' },
    t,
  );
  t += TIME.chatReveal + TIME.chatHoldShort;

  // -- the call actually reaching the gateway: AI Assistant -> Gateway --
  tl.call(
    () => gsap.set(dot, { x: () => centerX(client, rect()), y: () => bottomY(client, rect()) }),
    undefined,
    t,
  );
  tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
  t += TIME.dotFade;
  // The box stays lit until this exact moment -- the pulse is now actually
  // leaving it -- rather than clearing only once the dot lands elsewhere.
  tl.call(() => client.classList.remove(ACTIVE_CLASS), undefined, t);
  tl.to(
    dot,
    { y: () => topY(gateway, rect()), duration: TIME.travelLong, ease: 'power1.inOut' },
    t,
  );
  t += TIME.travelLong;
  tl.call(() => gateway.classList.add(ACTIVE_CLASS), undefined, t);
  tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
  t += TIME.dotFade + 0.1;

  // -- gateway checks: auth, policy, audit, in order --
  let denied = false;
  for (const key of ['auth', 'policy', 'audit'] as const) {
    const outcome = cycle.tagOutcomes[key];
    const el = tags[key];
    tl.call(() => setTagState(el, 'checking'), undefined, t);
    t += TIME.tagCheck;
    tl.call(() => setTagState(el, outcome), undefined, t);
    t += TIME.tagResolveHold;
    if (outcome === 'fail') denied = true;
  }

  if (denied) {
    // Rejected before ever reaching a backend -- the gateway flags red and
    // the pulse simply returns to the AI Assistant.
    tl.call(
      () => {
        gateway.classList.remove(ACTIVE_CLASS);
        gateway.classList.add(DENIED_CLASS);
      },
      undefined,
      t,
    );
    t += TIME.deniedGap;

    tl.call(
      () => gsap.set(dot, { x: () => centerX(gateway, rect()), y: () => topY(gateway, rect()) }),
      undefined,
      t,
    );
    tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
    t += TIME.dotFade;
    tl.call(() => gateway.classList.remove(DENIED_CLASS), undefined, t);
    tl.to(
      dot,
      { y: () => bottomY(client, rect()), duration: TIME.travelLong, ease: 'power1.inOut' },
      t,
    );
    t += TIME.travelLong;
    // Glow on, but no fade here -- the dot stays visible and continues
    // straight on into the shared "response completes the loop" leg below,
    // which is what actually clears this glow and the spinner, right as
    // the pulse starts moving again.
    tl.call(() => client.classList.add(ACTIVE_CLASS), undefined, t);
    t += 0.35;
  } else {
    // Authorized -- broker mints a credential (a round trip to the
    // credential box, alias for x509/condor-token/etc.), then the pulse
    // continues on to the target backend.
    const brokerEl = tags.broker;
    tl.call(() => setTagState(brokerEl, 'checking'), undefined, t);
    t += 0.15;

    tl.call(
      () => {
        credentialLabel.textContent = cycle.credentialLabel ?? '';
        const gw = gateway.getBoundingClientRect();
        const r = rect();
        gsap.set(credential, {
          x: gw.right - r.left + 20,
          y: gw.top - r.top + gw.height / 2 - credential.offsetHeight / 2,
        });
      },
      undefined,
      t,
    );
    tl.to(credential, { opacity: 1, duration: 0.2 }, t);
    t += 0.2;

    tl.call(
      () =>
        gsap.set(dot, {
          x: () => centerX(gateway, rect()) + gateway.offsetWidth / 2,
          y: () => centerY(gateway, rect()),
        }),
      undefined,
      t,
    );
    tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
    t += TIME.dotFade;
    tl.to(
      dot,
      {
        x: () => centerX(credential, rect()),
        y: () => centerY(credential, rect()),
        duration: TIME.travelMed,
        ease: 'power1.inOut',
      },
      t,
    );
    t += TIME.travelMed;
    tl.call(() => credential.classList.add(ACTIVE_CLASS), undefined, t);
    tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
    t += TIME.dotFade + TIME.creditHold;

    tl.call(
      () =>
        gsap.set(dot, {
          x: () => centerX(credential, rect()),
          y: () => centerY(credential, rect()),
        }),
      undefined,
      t,
    );
    tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
    t += TIME.dotFade;
    tl.call(() => credential.classList.remove(ACTIVE_CLASS), undefined, t);
    tl.to(
      dot,
      {
        x: () => centerX(gateway, rect()) + gateway.offsetWidth / 2,
        y: () => centerY(gateway, rect()),
        duration: TIME.travelMed,
        ease: 'power1.inOut',
      },
      t,
    );
    t += TIME.travelMed;
    tl.call(() => setTagState(brokerEl, 'ok'), undefined, t);
    tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
    tl.to(credential, { opacity: 0, duration: 0.3 }, t);
    t += 0.3;

    const target = cycle.target ? refs.leaves[cycle.target] : null;
    if (target) {
      tl.call(
        () =>
          gsap.set(dot, { x: () => centerX(gateway, rect()), y: () => bottomY(gateway, rect()) }),
        undefined,
        t,
      );
      tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
      t += TIME.dotFade;
      tl.call(() => gateway.classList.remove(ACTIVE_CLASS), undefined, t);
      tl.to(
        dot,
        { y: () => topY(fanout, rect()), duration: TIME.travelShort, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelShort;
      tl.to(
        dot,
        { x: () => centerX(target, rect()), duration: TIME.travelMed, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelMed;
      tl.to(
        dot,
        { y: () => topY(target, rect()), duration: TIME.travelShort, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelShort;
      tl.call(
        () => {
          target.classList.add(ACTIVE_CLASS);
          setTagState(target, 'checking');
        },
        undefined,
        t,
      );
      tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
      t += TIME.dotFade + 0.3;
      tl.call(() => setTagState(target, 'ok'), undefined, t);
      t += TIME.arrivalHold;

      // -- the return trip: target -> bus -> gateway -> AI Assistant --
      tl.call(
        () => gsap.set(dot, { x: () => centerX(target, rect()), y: () => topY(target, rect()) }),
        undefined,
        t,
      );
      tl.to(dot, { opacity: 1, duration: TIME.dotFade }, t);
      t += TIME.dotFade;
      tl.call(() => target.classList.remove(ACTIVE_CLASS), undefined, t);
      tl.to(
        dot,
        { y: () => topY(fanout, rect()), duration: TIME.travelShort, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelShort;
      tl.to(
        dot,
        { x: () => centerX(gateway, rect()), duration: TIME.travelMed, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelMed;
      tl.to(
        dot,
        { y: () => bottomY(gateway, rect()), duration: TIME.travelShort, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelShort;
      // No highlight on this last leg -- gateway and AI Assistant are just
      // being passed through on the way back, too briefly for a light-up
      // to read as anything but a flicker. The dot stays visible and
      // continues straight into the shared "response completes the loop"
      // leg below, rather than fading out and back in at AI Assistant.
      tl.to(
        dot,
        { y: () => bottomY(client, rect()), duration: TIME.travelLong, ease: 'power1.inOut' },
        t,
      );
      t += TIME.travelLong;
    }
  }

  // -- the response completes the loop: the same dot continues straight
  // through the AI Assistant box on to the chat log -- no fade in between,
  // so the pulse never stops moving. The spinner (and, for the denied
  // cycle, the border glow) clear right as this leg begins, so "waiting"
  // visibly ends the instant the pulse starts moving again, not before.
  // Arriving at the chat log is what causes the final line to appear,
  // mirroring the request's trip out at the start of this cycle.
  tl.call(
    () => {
      setTagState(client, '');
      client.classList.remove(ACTIVE_CLASS);
    },
    undefined,
    t,
  );
  tl.to(
    dot,
    {
      x: () => leftX(chatLines[2].wrapper, rect()),
      y: () => centerY(chatLines[2].wrapper, rect()),
      duration: TIME.travelMed,
      ease: 'power1.inOut',
    },
    t,
  );
  t += TIME.travelMed;
  tl.to(dot, { opacity: 0, duration: TIME.dotFade }, t);
  t += TIME.dotFade + 0.1;

  // -- chat: the assistant's final answer --
  tl.call(() => (chatLines[2].text.textContent = cycle.aiResultText), undefined, t);
  tl.to(
    chatLines[2].wrapper,
    { height: 'auto', opacity: 1, duration: TIME.chatReveal, ease: 'power2.out' },
    t,
  );
  t += TIME.chatReveal + TIME.chatHoldFinal;

  // -- reset: fade the chat log and clear every highlight/tag for the next cycle --
  tl.call(() => client.classList.remove(ACTIVE_CLASS), undefined, t);
  tl.to(
    chatLines.map((l) => l.wrapper),
    { height: 0, opacity: 0, duration: TIME.chatCollapse, ease: 'power2.in' },
    t,
  );
  tl.call(
    () => {
      setTagState(tags.auth, '');
      setTagState(tags.policy, '');
      setTagState(tags.audit, '');
      setTagState(tags.broker, '');
      if (cycle.target) setTagState(refs.leaves[cycle.target], '');
    },
    undefined,
    t,
  );
  return tl;
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

  const refs = resolveRefs(root);
  if (!refs) return () => {};

  const master = gsap.timeline({ repeat: -1, repeatDelay: 1.3, paused: true });
  for (const cycle of CYCLES) {
    master.add(buildCycleTimeline(cycle, refs));
  }

  const trigger = ScrollTrigger.create({
    trigger: root,
    start: 'top 85%',
    end: 'bottom 15%',
    onEnter: () => master.play(),
    onEnterBack: () => master.play(),
    onLeave: () => master.pause(),
    onLeaveBack: () => master.pause(),
  });

  return function cleanup(): void {
    master.kill();
    trigger.kill();
  };
}
