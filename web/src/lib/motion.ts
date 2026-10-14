/* editorial-ui · Cristian Pérez · cristianperez.me */
/**
 * Shared motion vocabulary. One easing curve for things that enter, one spring
 * for things the user moves. Everything else in the UI reuses these.
 */
export const ease = [0.22, 1, 0.36, 1] as [number, number, number, number];
export const spring = { type: "spring" as const, stiffness: 420, damping: 34, mass: 0.8 };
export const softSpring = { type: "spring" as const, stiffness: 500, damping: 30 };

/** Section entrance: fade and a short rise, once. */
export const reveal = {
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, amount: 0.05 },
  transition: { duration: 0.7, ease },
};
