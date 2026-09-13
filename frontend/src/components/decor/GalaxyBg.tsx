import React, { useMemo } from 'react';

interface Dot {
  left: number;
  top: number;
  size: number;
  color: string;
  alpha: number;
}

const COLORS = ['#ffffff', '#ffffff', '#9ec5ff', '#c4b5fd', '#ffd6aa'];

/**
 * Sparse random starfield. Fixed, pointer-transparent, zero layout effect.
 * Clearly visible yet quiet — the layer sits well below content prominence.
 */
export const GalaxyBg: React.FC = () => {
  const dots = useMemo<Dot[]>(
    () =>
      Array.from({ length: 260 }, () => ({
        left: Math.random() * 100,
        top: Math.random() * 100,
        size: Math.random() < 0.7 ? 1.5 : Math.random() < 0.8 ? 2 : 3,
        color: COLORS[Math.floor(Math.random() * COLORS.length)],
        alpha: 0.5 + Math.random() * 0.5,
      })),
    [],
  );

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-black" style={{ opacity: 0.5 }}>
      {dots.map((d, i) => (
        <span
          key={i}
          className="absolute rounded-full"
          style={{
            left: `${d.left}%`,
            top: `${d.top}%`,
            width: d.size,
            height: d.size,
            backgroundColor: d.color,
            opacity: d.alpha,
          }}
        />
      ))}
    </div>
  );
};
