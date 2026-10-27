import { describe, it, expect, vi } from "vitest";
import {
  ApiError,
  createApiClient,
  emptyResponse,
  key32,
  operationResponse,
  validDetail,
  validInstance,
  validNode,
  validPage,
  validResources,
  validSession,
} from "../src/api/client";
import { admin, instance, node, operation, resources } from "./fixtures";
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
describe("same-origin production transport", () => {
  it("has no demo fallback and sends exact cookie/CSRF/stable key", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(json({ operation }, 202));
    const client = createApiClient(fetcher);
    client.setCSRF("csrf-test");
    await client.write(
      "POST",
      `/instances/${instance.id}/operations`,
      { action: "start", confirmation: instance.id },
      operation.id,
      operationResponse,
      202,
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toBe(`/console/v1/instances/${instance.id}/operations`);
    expect(init).toMatchObject({
      method: "POST",
      credentials: "same-origin",
      mode: "same-origin",
      redirect: "error",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": "csrf-test",
        "Idempotency-Key": operation.id,
      },
    });
  });
  it.each([
    "https://evil.invalid",
    "//evil.invalid",
    "/../users",
    "/users#ignored",
  ])("rejects external or ambiguous path %s before sending", async (path) => {
    const fetcher = vi.fn<typeof fetch>();
    await expect(
      createApiClient(fetcher).get(path, emptyResponse),
    ).rejects.toMatchObject({ kind: "invalid" });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("rejects missing CSRF and malformed key before sending", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const api = createApiClient(fetcher);
    await expect(
      api.write("POST", "/users", {}, operation.id, emptyResponse),
    ).rejects.toMatchObject({ kind: "invalid" });
    api.setCSRF("csrf");
    await expect(
      api.write("POST", "/users", {}, "UPPERCASE", emptyResponse),
    ).rejects.toMatchObject({ kind: "invalid" });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("accepts an explicitly expected empty 204 logout without a JSON content type", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 204 }));
    const api = createApiClient(fetcher);
    api.setCSRF("csrf");
    await expect(
      api.write("POST", "/auth/logout", {}, operation.id, emptyResponse, 204),
    ).resolves.toEqual({});
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0]).toMatchObject([
      "/console/v1/auth/logout",
      {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-CSRF-Token": "csrf", "Idempotency-Key": operation.id },
      },
    ]);
  });
  it("does not accept 200 JSON as confirmation of the 204 logout contract", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({}));
    const api = createApiClient(fetcher);
    api.setCSRF("csrf");
    await expect(
      api.write("POST", "/auth/logout", {}, operation.id, emptyResponse, 204),
    ).rejects.toMatchObject({ kind: "unknown" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each([" ", "{}"])(
    "does not accept an unexpected body %j on a 204 logout",
    async (body) => {
      const response = new Response(null, { status: 204 });
      vi.spyOn(response, "text").mockResolvedValue(body);
      const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
      const api = createApiClient(fetcher);
      api.setCSRF("csrf");
      await expect(
        api.write("POST", "/auth/logout", {}, operation.id, emptyResponse, 204),
      ).rejects.toMatchObject({ kind: "unknown" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );
  it("still rejects a 204 when its explicitly supplied response guard does not match", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 204 }));
    const api = createApiClient(fetcher);
    api.setCSRF("csrf");
    await expect(
      api.write(
        "POST",
        "/auth/logout",
        {},
        operation.id,
        operationResponse,
        204,
      ),
    ).rejects.toMatchObject({ kind: "unknown" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("preserves an authenticated logout rejection rather than accepting its JSON error", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(json({ error: { code: "CSRF_REQUIRED" } }, 403));
    const api = createApiClient(fetcher);
    api.setCSRF("csrf");
    await expect(
      api.write("POST", "/auth/logout", {}, operation.id, emptyResponse, 204),
    ).rejects.toMatchObject({
      kind: "forbidden",
      code: "CSRF_REQUIRED",
      status: 403,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each([200, 201, 204])(
    "never turns unexpected ACK %i into accepted",
    async (status) => {
      const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
        status === 204
          ? new Response(null, {
              status,
              headers: { "Content-Type": "application/json" },
            })
          : json({ operation }, status),
      );
      const api = createApiClient(fetcher);
      api.setCSRF("csrf");
      await expect(
        api.write(
          "POST",
          "/instances",
          {},
          operation.id,
          operationResponse,
          202,
        ),
      ).rejects.toMatchObject({ kind: "unknown" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );
  it.each([200, 202])(
    "accepts only declared first/replay statuses for asynchronous resources (%i)",
    async (status) => {
      const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({}, status));
      const api = createApiClient(fetcher);
      api.setCSRF("csrf");
      await expect(
        api.write(
          "POST",
          "/public-ips/resources/" + operation.id + "/binding",
          {},
          operation.id,
          emptyResponse,
          [202, 200],
        ),
      ).resolves.toEqual({});
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );
  it("rejects an undeclared resource status without retry", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json({}, 201));
    const api = createApiClient(fetcher);
    api.setCSRF("csrf");
    await expect(
      api.write(
        "POST",
        "/public-ips/resources/" + operation.id + "/binding",
        {},
        operation.id,
        emptyResponse,
        [202, 200],
      ),
    ).rejects.toMatchObject({ kind: "unknown" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each(["network", "html", "shape", "500"])(
    "write %s is unknown and never automatically retried",
    async (mode) => {
      const fetcher = vi.fn<typeof fetch>();
      if (mode === "network")
        fetcher.mockRejectedValue(new TypeError("sensitive internal address"));
      else
        fetcher.mockResolvedValue(
          mode === "html"
            ? new Response("<html>private detail</html>", { status: 200 })
            : mode === "500"
              ? json({ error: { code: "DEPENDENCY_UNAVAILABLE" } }, 503)
              : json({ success: true }, 202),
        );
      const api = createApiClient(fetcher);
      api.setCSRF("csrf");
      await expect(
        api.write(
          "POST",
          "/instances",
          {},
          operation.id,
          operationResponse,
          202,
        ),
      ).rejects.toMatchObject({ kind: "unknown", message: "unknown" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    },
  );
  it.each([
    [401, "unauthorized"],
    [403, "forbidden"],
    [409, "conflict"],
    [400, "invalid"],
  ] as const)("classifies complete HTTP %i", async (status, kind) => {
    const api = createApiClient(
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(json({ error: { code: "STATE_CONFLICT" } }, status)),
    );
    api.setCSRF("csrf");
    await expect(
      api.write("POST", "/instances", {}, operation.id, operationResponse),
    ).rejects.toMatchObject({ kind, status });
  });
  it("keeps read network failures distinct and exposes no raw exception", async () => {
    const api = createApiClient(
      vi.fn<typeof fetch>().mockRejectedValue(new Error("password private")),
    );
    await expect(
      api.get("/instances", (v): v is { items: unknown[] } => !!v),
    ).rejects.toEqual(new ApiError("network"));
  });
  it("generates independent 32 lowercase hexadecimal IDs", () => {
    const keys = Array.from({ length: 100 }, key32);
    expect(new Set(keys).size).toBe(100);
    keys.forEach((key) => expect(key).toMatch(/^[a-f0-9]{32}$/));
  });
});
describe("typed server contracts", () => {
  it("requires plain data, live user grants and no legacy data envelope", () => {
    expect(validSession({ user: admin, csrf_token: "token" })).toBe(true);
    expect(validSession({ data: { user: admin, csrf_token: "token" } })).toBe(
      false,
    );
    expect(
      validSession({
        user: { ...admin, permissions: null },
        csrf_token: "token",
      }),
    ).toBe(false);
  });
  it("preserves unknown state case rather than inventing a success", () =>
    expect(validInstance({ ...instance, state: "VENDOR_UNKNOWN" })).toBe(true));
  it.each([
    -1,
    Number.MAX_SAFE_INTEGER + 1,
    1.5,
    NaN,
    Infinity,
    "2",
  ] as unknown[])("rejects unsafe resource number %s", (value) =>
    expect(validResources({ ...resources, cpu_cores: value })).toBe(false),
  );
  it("requires full resources and explicit cursor", () => {
    expect(validInstance(instance)).toBe(true);
    expect(
      validResources({ cpu_cores: 2, memory_mib: 4096, system_disk_gib: 40 }),
    ).toBe(false);
    expect(
      validPage({ items: [instance], next_cursor: null }, validInstance),
    ).toBe(true);
    expect(validPage({ items: [] }, validInstance)).toBe(false);
    expect(validNode(node)).toBe(true);
  });
  it("requires migration phase and all explicit collections", () => {
    const detail = {
      instance,
      operations: [operation],
      artifacts: [],
      migrations: [],
    };
    expect(validDetail(detail)).toBe(true);
    expect(validDetail({ ...detail, artifacts: null })).toBe(false);
    expect(
      validDetail({ ...detail, migrations: [{ id: "x", state: "prepared" }] }),
    ).toBe(false);
  });
});
