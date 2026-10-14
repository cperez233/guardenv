/* editorial-ui · Cristian Pérez · cristianperez.me */
import { AnimatePresence, motion, useSpring, useTransform } from "framer-motion";
import { useEffect, useRef } from "react";
import type { ReactElement } from "react";

import { ease } from "@/lib/motion";

/**
 * Integer that rolls in the direction it moved: up enters from below, down
 * enters from above. `tabular-nums` keeps the width steady while it rolls.
 */
export function RollingNumber({ value, className }: { value: number; className?: string }): ReactElement {
  const previous = useRef(value);
  const direction = value >= previous.current ? 1 : -1;
  useEffect(() => {
    previous.current = value;
  }, [value]);
  return (
    <span className={`relative inline-flex overflow-hidden tabular-nums ${className ?? ""}`}>
      <AnimatePresence initial={false} custom={direction} mode="popLayout">
        <motion.span
          key={value}
          custom={direction}
          variants={{
            enter: (d: number) => ({ y: `${d * 90}%`, opacity: 0 }),
            center: { y: "0%", opacity: 1 },
            exit: (d: number) => ({ y: `${d * -90}%`, opacity: 0 }),
          }}
          initial="enter"
          animate="center"
          exit="exit"
          transition={{ duration: 0.32, ease }}
          className="inline-block"
        >
          {value}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

/** A continuous value (a duration, a ratio) that springs between readings. */
export function SpringNumber({
  value,
  format,
  className,
}: {
  value: number;
  format: (value: number) => string;
  className?: string;
}): ReactElement {
  const mv = useSpring(value, { stiffness: 140, damping: 24 });
  useEffect(() => {
    mv.set(value);
  }, [mv, value]);
  const text = useTransform(mv, (v) => format(v));
  return <motion.span className={`tabular-nums ${className ?? ""}`}>{text}</motion.span>;
}
