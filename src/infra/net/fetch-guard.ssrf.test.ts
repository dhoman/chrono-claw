import { describe, expect, it, vi } from "vitest";
import { fetchWithSsrFGuard } from "./fetch-guard.js";

function redirectResponse(location: string): Response {
  return new Response(null, {
    status: 302,
    headers: { location },
  });
}

function okResponse(body = "ok"): Response {
  return new Response(body, { status: 200 });
}

describe("fetchWithSsrFGuard hardening", () => {
  type LookupFn = NonNullable<Parameters<typeof fetchWithSsrFGuard>[0]["lookupFn"]>;

  it("blocks private IP literal URLs before fetch", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://127.0.0.1:8080/internal",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks legacy loopback literal URLs before fetch", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://0177.0.0.1:8080/internal",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks unsupported packed-hex loopback literal URLs before fetch", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://0x7f000001/internal",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks redirect chains that hop to private hosts", async () => {
    const lookupFn = vi.fn(async () => [
      { address: "93.184.216.34", family: 4 },
    ]) as unknown as LookupFn;
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("http://127.0.0.1:6379/"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://public.example/start",
        fetchImpl,
        lookupFn,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("enforces hostname allowlist policies", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "https://evil.example.org/file.txt",
        fetchImpl,
        policy: { hostnameAllowlist: ["cdn.example.com", "*.assets.example.com"] },
      }),
    ).rejects.toThrow(/allowlist/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("allows wildcard allowlisted hosts", async () => {
    const lookupFn = vi.fn(async () => [
      { address: "93.184.216.34", family: 4 },
    ]) as unknown as LookupFn;
    const fetchImpl = vi.fn(async () => new Response("ok", { status: 200 }));
    const result = await fetchWithSsrFGuard({
      url: "https://img.assets.example.com/pic.png",
      fetchImpl,
      lookupFn,
      policy: { hostnameAllowlist: ["*.assets.example.com"] },
    });

    expect(result.response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    await result.release();
  });

  it("strips sensitive headers when redirect crosses origins", async () => {
    const lookupFn = vi.fn(async () => [
      { address: "93.184.216.34", family: 4 },
    ]) as unknown as LookupFn;
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse("https://cdn.example.com/asset"))
      .mockResolvedValueOnce(okResponse());

    const result = await fetchWithSsrFGuard({
      url: "https://api.example.com/start",
      fetchImpl,
      lookupFn,
      init: {
        headers: {
          Authorization: "Bearer secret",
          "Proxy-Authorization": "Basic c2VjcmV0",
          Cookie: "session=abc",
          Cookie2: "legacy=1",
          "X-Trace": "1",
        },
      },
    });

    const [, secondInit] = fetchImpl.mock.calls[1] as [string, RequestInit];
    const headers = new Headers(secondInit.headers);
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("proxy-authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("cookie2")).toBeNull();
    expect(headers.get("x-trace")).toBe("1");
    await result.release();
  });

  it("keeps headers when redirect stays on same origin", async () => {
    const lookupFn = vi.fn(async () => [
      { address: "93.184.216.34", family: 4 },
    ]) as unknown as LookupFn;
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse("/next"))
      .mockResolvedValueOnce(okResponse());

    const result = await fetchWithSsrFGuard({
      url: "https://api.example.com/start",
      fetchImpl,
      lookupFn,
      init: {
        headers: {
          Authorization: "Bearer secret",
        },
      },
    });

    const [, secondInit] = fetchImpl.mock.calls[1] as [string, RequestInit];
    const headers = new Headers(secondInit.headers);
    expect(headers.get("authorization")).toBe("Bearer secret");
    await result.release();
  });

  // =========================================================================
  // IP encoding variants (4 new)
  // =========================================================================

  it("blocks 0.0.0.0 (all-zeros IPv4)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://0.0.0.0:8080/",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks [::] (all-zeros IPv6)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://[::]:8080/",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks ::ffff:127.0.0.1 (IPv6-mapped-IPv4 loopback)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://[::ffff:127.0.0.1]:8080/",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks ::ffff:192.168.1.1 (IPv6-mapped-IPv4 private)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://[::ffff:192.168.1.1]:8080/",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Protocol injection (2 new)
  // =========================================================================

  it("rejects file:///etc/passwd (non-HTTP protocol)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "file:///etc/passwd",
        fetchImpl,
      }),
    ).rejects.toThrow(/http|https|invalid/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects data: protocol", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "data:text/html,<script>alert(1)</script>",
        fetchImpl,
      }),
    ).rejects.toThrow(/http|https|invalid/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  // =========================================================================
  // DNS-based attacks (3 new)
  // =========================================================================

  it("blocks redirect from public URL to file:// scheme (protocol downgrade)", async () => {
    const lookupFn = vi.fn(async () => [{ address: "93.184.216.34", family: 4 }]);
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("file:///etc/passwd"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://public.example/start",
        fetchImpl,
        lookupFn,
      }),
    ).rejects.toThrow(/http|https|invalid/i);
  });

  it("blocks DNS resolving to private IP via mock lookupFn", async () => {
    const lookupFn = vi.fn(async () => [{ address: "10.0.0.1", family: 4 }]);
    const fetchImpl = vi.fn();

    await expect(
      fetchWithSsrFGuard({
        url: "https://attacker-controlled.example.com/",
        fetchImpl,
        lookupFn,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("blocks redirect chain where second hop DNS resolves to 169.254.169.254", async () => {
    // First hop: public DNS, returns redirect to second domain
    // Second hop: DNS resolves to metadata endpoint
    let callCount = 0;
    const lookupFn = vi.fn(async (hostname: string) => {
      if (hostname === "hop2.attacker.example.com") {
        return [{ address: "169.254.169.254", family: 4 }];
      }
      return [{ address: "93.184.216.34", family: 4 }];
    });
    const fetchImpl = vi.fn(async () => {
      callCount++;
      if (callCount === 1) {
        return redirectResponse("https://hop2.attacker.example.com/latest/meta-data/");
      }
      return new Response("ok", { status: 200 });
    });

    await expect(
      fetchWithSsrFGuard({
        url: "https://hop1.attacker.example.com/",
        fetchImpl,
        lookupFn,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
  });

  // =========================================================================
  // URL parsing edge cases (3 new)
  // =========================================================================

  it("blocks http://[::1]/ (IPv6 loopback in brackets)", async () => {
    const fetchImpl = vi.fn();
    await expect(
      fetchWithSsrFGuard({
        url: "http://[::1]/",
        fetchImpl,
      }),
    ).rejects.toThrow(/private|internal|blocked/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("handles redirect loop detection (A -> B -> A cycle)", async () => {
    const lookupFn = vi.fn(async () => [{ address: "93.184.216.34", family: 4 }]);
    let callCount = 0;
    const fetchImpl = vi.fn(async () => {
      callCount++;
      if (callCount === 1) {
        return redirectResponse("https://b.example.com/");
      }
      return redirectResponse("https://a.example.com/");
    });

    await expect(
      fetchWithSsrFGuard({
        url: "https://a.example.com/",
        fetchImpl,
        lookupFn,
      }),
    ).rejects.toThrow(/redirect loop/i);
  });

  it("enforces max redirect limit", async () => {
    const lookupFn = vi.fn(async () => [{ address: "93.184.216.34", family: 4 }]);
    let callCount = 0;
    const fetchImpl = vi.fn(async () => {
      callCount++;
      return redirectResponse(`https://hop${callCount}.example.com/`);
    });

    await expect(
      fetchWithSsrFGuard({
        url: "https://start.example.com/",
        fetchImpl,
        lookupFn,
        maxRedirects: 2,
      }),
    ).rejects.toThrow(/too many redirects/i);
    expect(fetchImpl).toHaveBeenCalledTimes(3); // initial + 2 redirects, 3rd exceeds limit
  });

  // =========================================================================
  // Allowlist edge cases (2 new)
  // =========================================================================

  it("allowPrivateNetwork: true permits 127.0.0.1", async () => {
    const lookupFn = vi.fn(async () => [{ address: "127.0.0.1", family: 4 }]);
    const fetchImpl = vi.fn(async () => new Response("ok", { status: 200 }));
    const result = await fetchWithSsrFGuard({
      url: "http://127.0.0.1:8080/internal",
      fetchImpl,
      lookupFn,
      policy: { allowPrivateNetwork: true },
    });

    expect(result.response.status).toBe(200);
    await result.release();
  });

  it("empty hostnameAllowlist blocks non-matching hosts", async () => {
    const fetchImpl = vi.fn();
    // An allowlist with a specific entry should block anything not matching
    await expect(
      fetchWithSsrFGuard({
        url: "https://unauthorized.example.com/",
        fetchImpl,
        policy: { hostnameAllowlist: ["only-this.example.com"] },
      }),
    ).rejects.toThrow(/allowlist/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
