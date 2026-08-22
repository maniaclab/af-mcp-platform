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
// storyboard rather than a wall of magic numbers. Grouped by the beat they
// belong to, in roughly the order that beat first appears in a cycle.
const TIME = {
  // Chat log
  chatReveal: 0.3, // a line's own height/opacity reveal
  chatHoldShort: 0.55, // pause after the USER line, and after the tool_call line
  chatHoldFinal: 1.9, // pause after the final result line, before the reset
  chatCollapse: 0.4, // the whole log folding away at the reset
  thinkHold: 0.8, // "AI is deciding" -- between arriving at AI Assistant and the tool_call line appearing
  clearOffset: 0.12, // how far into the final return leg the spinner/glow actually clears (see buildCycleTimeline's last section)

  // The pulse dot
  dotFade: 0.15, // its own appear/vanish fade
  travelShort: 0.3, // a short hop (e.g. gateway <-> the fanout bus)
  travelMed: 0.4, // a medium hop (e.g. across the bus to a leaf's x, or to/from the credential box)
  travelLong: 0.55, // the long hop between AI Assistant and the gateway
  settleGap: 0.1, // a brief beat after a vanish, before the next phase begins

  // Gateway tag checks (auth/policy/audit) and the credential round trip
  tagCheck: 0.22, // a tag's own spinner duration
  tagResolveHold: 0.18, // pause after a tag resolves, before the next one starts checking
  deniedGap: 0.55, // long enough for DENIED_CLASS's 3x160ms CSS buzz (index.astro's diagram-denied-buzz keyframe) to finish before it's removed
  brokerCheckDelay: 0.15, // pause after Broker starts spinning, before the credential box appears
  credentialAppear: 0.2, // the credential box's own fade-in
  creditHold: 0.35, // "minting" pause once the pulse arrives at the credential box
  credentialVanish: 0.3, // the credential box's own fade-out, once the broker check resolves
  targetCheckHold: 0.3, // a backend's own spinner duration before it resolves to ok
  arrivalHold: 0.45, // pause after a backend resolves to ok, before the return trip starts
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

function rightX(el: Element, containerRect: DOMRect): number {
  return el.getBoundingClientRect().right - containerRect.left;
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

/**
 * A tiny position-tracking wrapper around a GSAP timeline. Every method
 * schedules its animation at the sequencer's own time cursor and advances
 * that cursor by the animation's duration, so a cycle's script below reads
 * as a plain top-to-bottom list of "then this happens" beats instead of a
 * hand-maintained `t += ...` after every single call -- the actual source
 * of a couple of real timing bugs caught by hand while this animation was
 * first built. `.time` is only needed for the one case (the final return
 * leg's delayed clear) where something must happen partway *into* an
 * animation rather than at its start or end.
 */
class Sequencer {
  private t = 0;

  constructor(private readonly tl: gsap.core.Timeline) {}

  get time(): number {
    return this.t;
  }

  /** Runs `fn` at the current time; doesn't advance the cursor. */
  mark(fn: () => void): this {
    this.tl.call(fn, undefined, this.t);
    return this;
  }

  /** Runs `fn` `offset` seconds into whatever's currently scheduled, without moving the cursor. */
  markAt(fn: () => void, offset: number): this {
    this.tl.call(fn, undefined, this.t + offset);
    return this;
  }

  /** Advances the cursor with nothing scheduled -- a pure hold. */
  wait(duration: number): this {
    this.t += duration;
    return this;
  }

  /** A generic tween at the current time, advancing the cursor by `duration`. */
  tween(target: gsap.TweenTarget, vars: gsap.TweenVars, duration: number): this {
    this.tl.to(target, { ...vars, duration }, this.t);
    this.t += duration;
    return this;
  }

  /** Same as `tween`, but leaves the cursor where it was -- for the one
   * place two independent tweens (of differing duration) need to start
   * together, where the caller advances the cursor itself afterward. */
  tweenConcurrent(target: gsap.TweenTarget, vars: gsap.TweenVars, duration: number): this {
    this.tl.to(target, { ...vars, duration }, this.t);
    return this;
  }

  /** The pulse dot's x/y travel -- every dot movement in this file uses the same ease. */
  moveTo(el: HTMLElement, vars: { x?: () => number; y?: () => number }, duration: number): this {
    return this.tween(el, { ...vars, ease: 'power1.inOut' }, duration);
  }

  /** Instantly repositions `el` (while invisible) then fades it in over `TIME.dotFade`. */
  appear(el: HTMLElement, x: () => number, y: () => number): this {
    this.mark(() => gsap.set(el, { x, y }));
    return this.tween(el, { opacity: 1 }, TIME.dotFade);
  }

  /** Fades `el` out in place over `TIME.dotFade`. */
  vanish(el: HTMLElement): this {
    return this.tween(el, { opacity: 0 }, TIME.dotFade);
  }

  /** The shared "spinner, then resolve" beat used by every gateway tag and backend check. */
  checkTag(el: HTMLElement, outcome: TagState): this {
    return this.mark(() => setTagState(el, 'checking'))
      .wait(TIME.tagCheck)
      .mark(() => setTagState(el, outcome))
      .wait(TIME.tagResolveHold);
  }
}

/** Builds one cycle's fully-scripted timeline. Every position is a function
 * re-evaluated at play time, so this is safe to build once and let a parent
 * timeline repeat indefinitely. */
function buildCycleTimeline(cycle: Cycle, refs: Refs): gsap.core.Timeline {
  const tl = gsap.timeline();
  const seq = new Sequencer(tl);
  const rect = () => refs.root.getBoundingClientRect();
  const { client, gateway, fanout, credential, credentialLabel, dot, tags, chatLines } = refs;

  // Text is set inside a .call() rather than assigned directly here --
  // buildCycleTimeline() runs for all three cycles up front (see the loop
  // in initGatewayPulse), and the three cycles share the same DOM
  // elements, so a direct assignment here would have the last cycle built
  // silently overwrite the first two's text before anything ever played.
  function revealChatLine(index: 0 | 1 | 2, text: string): void {
    seq.mark(() => (chatLines[index].text.textContent = text));
    seq.tween(
      chatLines[index].wrapper,
      { height: 'auto', opacity: 1, ease: 'power2.out' },
      TIME.chatReveal,
    );
  }

  // -- chat: user's request --
  revealChatLine(0, cycle.userText);
  seq.wait(TIME.chatHoldShort);

  // -- a small dot carries the request from the chat log to the AI
  // Assistant box, which then "thinks" (spinner) before it decides on a
  // tool call -- a beat between the user's message landing and the
  // assistant's response appearing. Both the spinner and the border glow
  // deliberately keep going past this beat -- the box is still "occupied"
  // through the tool_call line below, and only clear once the pulse
  // actually departs toward the gateway, much later. --
  seq.appear(
    dot,
    () => leftX(chatLines[0].wrapper, rect()),
    () => centerY(chatLines[0].wrapper, rect()),
  );
  seq.moveTo(
    dot,
    { x: () => centerX(client, rect()), y: () => centerY(client, rect()) },
    TIME.travelMed,
  );
  seq.mark(() => {
    client.classList.add(ACTIVE_CLASS);
    setTagState(client, 'checking');
  });
  seq.vanish(dot);
  seq.wait(TIME.thinkHold);

  // -- chat: the assistant's resulting tool call --
  revealChatLine(1, cycle.aiCallText);
  seq.wait(TIME.chatHoldShort);

  // -- the call actually reaching the gateway: AI Assistant -> Gateway --
  seq.appear(
    dot,
    () => centerX(client, rect()),
    () => bottomY(client, rect()),
  );
  // The box stays lit until this exact moment -- the pulse is now actually
  // leaving it -- rather than clearing only once the dot lands elsewhere.
  seq.mark(() => client.classList.remove(ACTIVE_CLASS));
  seq.moveTo(dot, { y: () => topY(gateway, rect()) }, TIME.travelLong);
  seq.mark(() => gateway.classList.add(ACTIVE_CLASS));
  seq.vanish(dot);
  seq.wait(TIME.settleGap);

  // -- gateway checks: auth, policy, audit, in order --
  let denied = false;
  for (const key of ['auth', 'policy', 'audit'] as const) {
    const outcome = cycle.tagOutcomes[key];
    seq.checkTag(tags[key], outcome);
    if (outcome === 'fail') denied = true;
  }

  if (denied) {
    // Rejected before ever reaching a backend -- the gateway buzzes red
    // and the pulse simply returns to the AI Assistant, with no highlight
    // there either (same reasoning as the authorized cycles' final leg,
    // below): it's just passing through on the way back.
    seq.mark(() => {
      gateway.classList.remove(ACTIVE_CLASS);
      gateway.classList.add(DENIED_CLASS);
    });
    seq.wait(TIME.deniedGap);
    seq.appear(
      dot,
      () => centerX(gateway, rect()),
      () => topY(gateway, rect()),
    );
    seq.mark(() => gateway.classList.remove(DENIED_CLASS));
    // Targets centerY, not bottomY -- the incoming chat->AI Assistant leg
    // (above) already arrives at centerY, and this return trip should
    // land on that same horizontal line rather than a lower one.
    seq.moveTo(dot, { y: () => centerY(client, rect()) }, TIME.travelLong);
  } else {
    // Authorized -- broker mints a credential (a round trip to the
    // credential box, alias for x509/condor-token/etc.), then the pulse
    // continues on to the target backend.
    const brokerEl = tags.broker;
    seq.mark(() => setTagState(brokerEl, 'checking'));
    seq.wait(TIME.brokerCheckDelay);

    seq.mark(() => {
      credentialLabel.textContent = cycle.credentialLabel ?? '';
      const gw = gateway.getBoundingClientRect();
      const r = rect();
      gsap.set(credential, {
        x: gw.right - r.left + 20,
        y: gw.top - r.top + gw.height / 2 - credential.offsetHeight / 2,
      });
    });
    seq.tween(credential, { opacity: 1 }, TIME.credentialAppear);

    // -- gateway <-> credential round trip --
    seq.appear(
      dot,
      () => rightX(gateway, rect()),
      () => centerY(gateway, rect()),
    );
    seq.moveTo(
      dot,
      { x: () => centerX(credential, rect()), y: () => centerY(credential, rect()) },
      TIME.travelMed,
    );
    seq.mark(() => credential.classList.add(ACTIVE_CLASS));
    seq.vanish(dot);
    seq.wait(TIME.creditHold);

    seq.appear(
      dot,
      () => centerX(credential, rect()),
      () => centerY(credential, rect()),
    );
    seq.mark(() => credential.classList.remove(ACTIVE_CLASS));
    seq.moveTo(
      dot,
      { x: () => rightX(gateway, rect()), y: () => centerY(gateway, rect()) },
      TIME.travelMed,
    );
    seq.mark(() => setTagState(brokerEl, 'ok'));
    // Both fades start together (the dot arriving back, the credential box
    // itself disappearing) -- tweenConcurrent leaves the cursor where it
    // was so the following advancing tween sets the pace for both.
    seq.tweenConcurrent(dot, { opacity: 0 }, TIME.dotFade);
    seq.tween(credential, { opacity: 0 }, TIME.credentialVanish);

    const target = cycle.target ? refs.leaves[cycle.target] : null;
    if (target) {
      // -- gateway -> bus -> target --
      seq.appear(
        dot,
        () => centerX(gateway, rect()),
        () => bottomY(gateway, rect()),
      );
      seq.mark(() => gateway.classList.remove(ACTIVE_CLASS));
      seq.moveTo(dot, { y: () => topY(fanout, rect()) }, TIME.travelShort);
      seq.moveTo(dot, { x: () => centerX(target, rect()) }, TIME.travelMed);
      seq.moveTo(dot, { y: () => topY(target, rect()) }, TIME.travelShort);
      seq.mark(() => {
        target.classList.add(ACTIVE_CLASS);
        setTagState(target, 'checking');
      });
      seq.vanish(dot);
      seq.wait(TIME.targetCheckHold);
      seq.mark(() => setTagState(target, 'ok'));
      seq.wait(TIME.arrivalHold);

      // -- the return trip: target -> bus -> gateway -> AI Assistant --
      // No highlight on gateway or AI Assistant here -- both are just
      // being passed through on the way back, too briefly for a light-up
      // to read as anything but a flicker. The dot stays visible the
      // whole way and continues straight into the shared "response
      // completes the loop" leg below, rather than fading out and back in
      // at AI Assistant. Targets centerY, not bottomY -- see the denied
      // cycle's identical comment above.
      seq.appear(
        dot,
        () => centerX(target, rect()),
        () => topY(target, rect()),
      );
      seq.mark(() => target.classList.remove(ACTIVE_CLASS));
      seq.moveTo(dot, { y: () => topY(fanout, rect()) }, TIME.travelShort);
      seq.moveTo(dot, { x: () => centerX(gateway, rect()) }, TIME.travelMed);
      seq.moveTo(dot, { y: () => bottomY(gateway, rect()) }, TIME.travelShort);
      seq.moveTo(dot, { y: () => centerY(client, rect()) }, TIME.travelLong);
    }
  }

  // -- the response completes the loop: the same dot continues straight
  // through the AI Assistant box on to the chat log -- no fade in between,
  // so the pulse never stops moving. Arriving at the chat log is what
  // causes the final line to appear, mirroring the request's trip out at
  // the start of this cycle.
  //
  // The spinner (and, for the denied cycle, the border glow) clear a beat
  // *into* this leg's motion rather than at its exact start -- removing a
  // class is instantaneous, but the eased tween ramps up gently, so
  // clearing at the very start reads as "cleared on arrival, while still
  // sitting in AI Assistant" for the first rendered frame or two.
  // Clearing after the pulse has visibly started moving reads
  // unambiguously as "cleared because it's leaving."
  seq.markAt(() => {
    setTagState(client, '');
    client.classList.remove(ACTIVE_CLASS);
  }, TIME.clearOffset);
  seq.moveTo(
    dot,
    {
      x: () => leftX(chatLines[2].wrapper, rect()),
      y: () => centerY(chatLines[2].wrapper, rect()),
    },
    TIME.travelMed,
  );
  seq.vanish(dot);
  seq.wait(TIME.settleGap);

  // -- chat: the assistant's final answer --
  revealChatLine(2, cycle.aiResultText);
  seq.wait(TIME.chatHoldFinal);

  // -- reset: fade the chat log and clear every highlight/tag for the next cycle --
  seq.mark(() => client.classList.remove(ACTIVE_CLASS));
  seq.tween(
    chatLines.map((l) => l.wrapper),
    { height: 0, opacity: 0, ease: 'power2.in' },
    TIME.chatCollapse,
  );
  seq.mark(() => {
    setTagState(tags.auth, '');
    setTagState(tags.policy, '');
    setTagState(tags.audit, '');
    setTagState(tags.broker, '');
    if (cycle.target) setTagState(refs.leaves[cycle.target], '');
  });

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
