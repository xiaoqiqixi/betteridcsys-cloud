// Shared DOM modality, not business state. Only the top dialog handles focus,
// Escape and Back; closing a child must not unlock its still-open parent.
interface Layer {
  root: HTMLElement;
  token: string;
  url: string;
}
const layers: Layer[] = [];
const originalInert = new Map<HTMLElement, boolean>();
const retired = new Map<string, string>();
const handled = new WeakSet<Event>();
let overflow = "",
  observer: MutationObserver | undefined,
  listening = false;
export function resetOrphanedOverlayHistory() {
  // A full reload does not unmount the former dialog. Its UI-only history
  // marker survives, but its DOM layer does not. Never navigate on startup,
  // discard router state, touch pending operations or reset a live layer.
  if (layers.length || retired.size) return;
  const state: unknown = history.state;
  if (!state || typeof state !== "object" || Array.isArray(state)) return;
  const token = (state as Record<string, unknown>).asterOverlay;
  if (typeof token !== "string" || !/^cloud-[a-f0-9]{32}$/.test(token)) return;
  const restored = { ...state } as Record<string, unknown>;
  delete restored.asterOverlay;
  history.replaceState(restored, "");
}
function capturePop(event: PopStateEvent) {
  const token: unknown = history.state?.asterOverlay;
  if (typeof token !== "string" || retired.get(token) !== location.href) return;
  // A session change may remove a parent and child in one render. Consume
  // only our own orphaned overlay entry, never another URL/router entry.
  retired.delete(token);
  handled.add(event);
  if (!layers.length && !retired.size) {
    window.removeEventListener("popstate", capturePop, true);
    listening = false;
  }
  history.back();
}
function sync() {
  const top = layers.at(-1)?.root;
  for (const child of document.body.children) {
    if (!(child instanceof HTMLElement)) continue;
    if (!originalInert.has(child))
      originalInert.set(child, Boolean(child.inert));
    child.inert = child !== top && !(top && child.contains(top));
  }
  layers.forEach((v, i) => {
    if (!originalInert.has(v.root))
      originalInert.set(v.root, Boolean(v.root.inert));
    v.root.inert = v.root !== top;
    v.root.style.zIndex = String(100 + i);
  });
}
export function isTopOverlay(root: HTMLElement | null) {
  return !!root && layers.at(-1)?.root === root;
}
export function overlayPopHandled(event: Event) {
  return handled.has(event);
}
export function handleOverlayPop(event: Event) {
  handled.add(event);
}
export function enterOverlay(root: HTMLElement, token: string, url: string) {
  if (!layers.length) {
    overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  if (!listening) {
    window.addEventListener("popstate", capturePop, true);
    listening = true;
  }
  layers.push({ root, token, url });
  sync();
  if (!observer) {
    observer = new MutationObserver(sync);
    observer.observe(document.body, { childList: true });
  }
}
export function leaveOverlay(root: HTMLElement) {
  const i = layers.findIndex((v) => v.root === root);
  if (i < 0) return false;
  const wasTop = i === layers.length - 1,
    layer = layers[i]!;
  if (
    !wasTop &&
    history.state?.asterOverlay !== layer.token &&
    location.href === layer.url
  )
    retired.set(layer.token, layer.url);
  layers.splice(i, 1);
  if (layers.length) sync();
  else {
    observer?.disconnect();
    observer = undefined;
    for (const [element, value] of originalInert) element.inert = value;
    originalInert.clear();
    document.body.style.overflow = overflow;
    if (!retired.size) {
      window.removeEventListener("popstate", capturePop, true);
      listening = false;
    }
  }
  return wasTop;
}
