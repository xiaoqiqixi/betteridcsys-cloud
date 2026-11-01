import RFB from './novnc/core/rfb.js';

// The fragment never reaches HTTP or referrers. Remove it before opening WSS.
const ticket = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
const status = document.getElementById('status');
const screen = document.getElementById('screen');
const disconnect = document.getElementById('disconnect');
const keys = document.getElementById('keys');
let rfb;
let escapes = [];
const end = (message) => {
  status.textContent = message;
  keys.disabled = true;
  disconnect.disabled = true;
};
if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
  end('This console link is unavailable. Open a new console from your service page.');
} else {
  try {
    rfb = new RFB(screen, `wss://${location.host}/console/ws?ticket=${ticket}`, { wsProtocols: ['binary'] });
    rfb.scaleViewport = true;
    rfb.resizeSession = false;
    rfb.addEventListener('connect', () => {
      status.textContent = 'Connected';
      disconnect.disabled = false;
      keys.disabled = false;
      const canvas = screen.querySelector('canvas');
      if (canvas) canvas.tabIndex = 0;
      canvas?.setAttribute('aria-label', 'Remote guest display. Press Escape three times to return to controls.');
    });
    rfb.addEventListener('disconnect', () => end('Disconnected. Open a new console from your service page to reconnect.'));
    rfb.addEventListener('securityfailure', () => { rfb.disconnect(); end('The console connection could not be verified. Open a new console from your service page.'); });
    rfb.addEventListener('credentialsrequired', () => { rfb.disconnect(); end('The console is unavailable. Contact your service provider.'); });
    disconnect.addEventListener('click', () => { rfb.disconnect(); end('Disconnected. You can close this tab.'); });
    keys.addEventListener('click', () => rfb.sendCtrlAltDel());
    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') { escapes = []; return; }
      const now = performance.now();
      escapes = escapes.filter(at => now - at < 1500);
      escapes.push(now);
      if (escapes.length === 3) {
        event.preventDefault(); event.stopImmediatePropagation(); escapes = [];
        rfb.blur(); disconnect.focus();
      }
    }, { capture: true });
    window.addEventListener('pagehide', () => rfb.disconnect(), { once: true });
  } catch {
    end('The console is unavailable. Open a new console from your service page.');
  }
}
