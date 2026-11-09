/*
  Taskbar clock: fills the empty, aria-hidden [data-slot="clock"] span (index.html) with the
  current time, like the Windows notification-area clock. Read-only DOM text, nothing else. The
  interval is stopped while the tab is hidden and restarts (after one tick) when shown.
*/

const FORMAT = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const UPDATE_MS = 15_000; // frequent enough that the minute rollover feels live

export function initClock() {
  const slot = document.querySelector('[data-slot="clock"]');
  if (!slot) return;
  const tick = () => {
    slot.textContent = FORMAT.format(new Date());
  };
  let interval = null;
  const start = () => {
    tick();
    clearInterval(interval);
    interval = setInterval(tick, UPDATE_MS);
  };
  const stop = () => {
    clearInterval(interval);
    interval = null;
  };
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  if (!document.hidden) start();
}
