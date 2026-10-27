import { shallowRef, watch } from "vue";
export type Locale = "zh-CN" | "en";
export type Appearance = "system" | "light" | "dark";
export function readPreferences(storage: Pick<Storage, "getItem"> | undefined) {
  try {
    const value = JSON.parse(storage?.getItem("aster.cloud.ui.v1") || "null");
    return {
      locale: value?.locale === "en" ? ("en" as const) : ("zh-CN" as const),
      appearance: ["system", "light", "dark"].includes(value?.appearance)
        ? (value.appearance as Appearance)
        : ("system" as const),
    };
  } catch {
    return { locale: "zh-CN" as const, appearance: "system" as const };
  }
}
export function usePreferences() {
  let storage: Storage | undefined;
  try {
    storage = localStorage;
  } catch {
    /* Storage is optional. */
  }
  const initial = readPreferences(storage);
  const locale = shallowRef<Locale>(initial.locale),
    appearance = shallowRef<Appearance>(initial.appearance);
  const media = matchMedia("(prefers-color-scheme: dark)");
  const systemDark = shallowRef(media.matches);
  const change = (event: MediaQueryListEvent) =>
    (systemDark.value = event.matches);
  media.addEventListener("change", change);
  watch(
    [locale, appearance, systemDark],
    () => {
      document.documentElement.lang = locale.value;
      document.documentElement.dataset.theme =
        appearance.value === "system"
          ? systemDark.value
            ? "dark"
            : "light"
          : appearance.value;
      try {
        storage?.setItem(
          "aster.cloud.ui.v1",
          JSON.stringify({
            locale: locale.value,
            appearance: appearance.value,
          }),
        );
      } catch {
        /* Continue without persistence. */
      }
    },
    { immediate: true },
  );
  return {
    locale,
    appearance,
    tr: (zh: string, en: string) => (locale.value === "zh-CN" ? zh : en),
    dispose: () => media.removeEventListener("change", change),
  };
}
