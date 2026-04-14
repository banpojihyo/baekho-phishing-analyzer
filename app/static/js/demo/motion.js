let motionObserver = null;
const motionCleanupTimers = new WeakMap();
const isCaptureMode =
  new URLSearchParams(window.location.search).get("capture") === "1";

function uniqueNodes(nodes) {
  return [...new Set((nodes || []).filter(Boolean))];
}

export function initializeMotionObserver() {
  document.body?.classList.add("js-motion");
  if (
    isCaptureMode ||
    window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
    typeof IntersectionObserver === "undefined"
  ) {
    motionObserver = null;
    return;
  }

  motionObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) {
          return;
        }
        entry.target.classList.add("is-visible");
        motionObserver?.unobserve(entry.target);
      });
    },
    {
      threshold: 0.18,
      rootMargin: "0px 0px -10% 0px",
    },
  );
}

export function registerMotionTargets(nodes, options = {}) {
  const { baseDelay = 0, step = 55 } = options;
  const targets = uniqueNodes(nodes);
  if (!targets.length) {
    return;
  }

  document.body?.classList.add("js-motion");
  targets.forEach((node, index) => {
    node.classList.add("motion-reveal");
    node.style.setProperty("--reveal-delay", `${baseDelay + index * step}ms`);
    if (motionObserver) {
      motionObserver.observe(node);
      return;
    }
    node.classList.add("is-visible");
  });
}

export function flashUpdatedSurfaces(nodes) {
  uniqueNodes(nodes).forEach((node) => {
    const pendingTimer = motionCleanupTimers.get(node);
    if (pendingTimer) {
      window.clearTimeout(pendingTimer);
    }
    node.classList.remove("is-updated");
    void node.offsetWidth;
    node.classList.add("is-updated");
    const cleanupTimer = window.setTimeout(() => {
      node.classList.remove("is-updated");
      motionCleanupTimers.delete(node);
    }, 820);
    motionCleanupTimers.set(node, cleanupTimer);
  });
}

export function setupStaticMotion() {
  initializeMotionObserver();
  registerMotionTargets(
    [
      ...document.querySelectorAll(
        ".demo-proof-card, .demo-hero-panel, .demo-band, .demo-section-head, .panel, .result-hero, .demo-anatomy-card, .demo-flow-step",
      ),
    ],
    { step: 45 },
  );
}
