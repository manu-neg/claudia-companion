/*
  Menu-bar clock: fills the empty [data-slot="clock"] span (index.html,
  already aria-hidden and decorative) with the current time, like the
  classic Mac OS menu-bar clock. Read-only DOM text, no other side effects.
*/

const FORMAT = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const UPDATE_MS = 15_000; // frequent enough that the minute rollover feels live

export function initClock() {
  const slot = document.querySelector('[data-slot="clock"]');
  if (!slot) return;
  const tick = () => {
    slot.textContent = FORMAT.format(new Date());
  };
  tick();
  setInterval(tick, UPDATE_MS);
}
