import { OSVClient } from "../src/lib/osv-client";

const mockOSVFetch = (
  ...responses: Array<Record<string, unknown>>
): jest.Mock => {
  let responseIndex = 0;
  return jest.fn(async () => {
    const response = responses[responseIndex++] || { vulns: [] };
    return {
      ok: true,
      status: 200,
      json: async () => response,
    };
  });
};

type MockLogger = {
  debug: jest.Mock;
  warn: jest.Mock;
  error: jest.Mock;
};

const createLogger = (): MockLogger => ({
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
});

describe("OSV client", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("fetches package advisories without version and follows pagination", async () => {
    const fetchMock = mockOSVFetch(
      { vulns: [], next_page_token: "page-2" },
      { vulns: [] },
    );

    const client = new OSVClient({
      fetchImpl: fetchMock as unknown as typeof fetch,
    }, createLogger());

    await client.fetchVulnerabilities("left-pad");

    const firstBody = JSON.parse((fetchMock.mock.calls[0][1] as any).body);
    const secondBody = JSON.parse((fetchMock.mock.calls[1][1] as any).body);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(firstBody).toEqual({
      package: {
        name: "left-pad",
        ecosystem: "npm",
      },
    });
    expect(secondBody).toEqual({
      package: {
        name: "left-pad",
        ecosystem: "npm",
      },
      page_token: "page-2",
    });
  });

  it("throws when OSV requests fail after all retries", async () => {
    const fetchMock = jest.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    }));
    const logger = createLogger();
    const client = new OSVClient({
      fetchImpl: fetchMock as unknown as typeof fetch,
      maxRetries: 1,
      retryDelayMs: 0,
    }, logger);

    await expect(client.fetchVulnerabilities("left-pad")).rejects.toThrow("OSV API returned 500");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logger.error).toHaveBeenCalledWith(
      "[OSV Client] OSV API error after 1 attempts:",
      "OSV API returned 500",
    );
  });

  it("normalizes OSV vulnerabilities for the target package", () => {
    const client = new OSVClient({}, createLogger());
    const normalized = client.normalizeOSVVulnerability(
      {
        id: "GHSA-test",
        details: "Example details",
        severity: [{ type: "CVSS_V3", score: "8.0" }],
        published: "2025-01-01T00:00:00Z",
        affected: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            ranges: [
              {
                type: "SEMVER",
                events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
              },
            ],
            versions: ["1.5.0"],
          },
          {
            package: {
              name: "other",
              ecosystem: "npm",
            },
            versions: ["9.9.9"],
          },
        ],
      },
      "lodash",
    );

    expect(normalized).toEqual(
      expect.objectContaining({
        id: "GHSA-test",
        severity: "high",
        summary: "Example details",
        affectedVersions: ["1.5.0"],
        introducedVersion: "1.0.0",
        fixedVersion: "2.0.0",
        publishedDate: "2025-01-01T00:00:00Z",
        source: "osv",
      }),
    );
    expect(normalized?.affected).toHaveLength(1);
  });

  it("returns null when an advisory does not affect the requested package", () => {
    const client = new OSVClient({}, createLogger());
    const normalized = client.normalizeOSVVulnerability(
      {
        id: "GHSA-test",
        affected: [
          {
            package: {
              name: "other",
              ecosystem: "npm",
            },
            versions: ["1.0.0"],
          },
        ],
      },
      "lodash",
    );

    expect(normalized).toBeUndefined();
  });

  it("uses the configured ecosystem when filtering affected packages", () => {
    const client = new OSVClient({
      ecosystem: "Linux",
    }, createLogger());
    const normalized = client.normalizeOSVVulnerability(
      {
        id: "GHSA-ecosystem",
        affected: [
          {
            package: {
              name: "Kernel",
              ecosystem: "npm",
            },
            versions: ["1.0.0"],
          },
          {
            package: {
              name: "Kernel",
              ecosystem: "Linux",
            },
            versions: ["6.0.0"],
          },
        ],
      },
      "Kernel",
    );

    expect(normalized?.affected).toHaveLength(1);
    expect(normalized?.affectedVersions).toEqual(["6.0.0"]);
  });

  it("matches versions inside OSV semver ranges", () => {
    const client = new OSVClient({}, createLogger());
    const range = {
      type: "SEMVER",
      events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
    };

    expect(client.matchOSVRange("0.9.0", range)).toBeUndefined();
    expect(client.matchOSVRange("1.5.0", range)).toEqual({
      introducedVersion: "1.0.0",
      fixedVersion: "2.0.0",
    });
    expect(client.matchOSVRange("2.0.0", range)).toBeUndefined();
  });

  it("matches versions from explicit OSV affected versions", () => {
    const client = new OSVClient({}, createLogger());
    const normalized = client.normalizeOSVVulnerability(
      {
        id: "GHSA-explicit",
        severity: [{ type: "CVSS_V3", score: "9.8" }],
        affected: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            versions: ["1.5.0"],
          },
        ],
      },
      "lodash",
    );

    expect(normalized).not.toBeUndefined();
    expect(client.matchVulnerabilityForVersion(normalized!, "lodash", "1.5.0")).toEqual(
      expect.objectContaining({
        id: "GHSA-explicit",
      }),
    );
    expect(client.matchVulnerabilityForVersion(normalized!, "lodash", "1.6.0")).toBeUndefined();
  });

  it("maps OSV severity shapes into plugin severity levels", () => {
    const client = new OSVClient({}, createLogger());

    expect(client.mapOSVSeverity([{ type: "CVSS_V3", score: "9.8" }])).toBe("critical");
    expect(client.mapOSVSeverity([{ type: "CVSS_V3", score: "7.2" }])).toBe("high");
    expect(client.mapOSVSeverity([{ type: "CVSS_V3", score: "5.0" }])).toBe("medium");
    expect(client.mapOSVSeverity([{ type: "CVSS_V3", score: "3.9" }])).toBe("low");
    expect(client.mapOSVSeverity("moderate")).toBe("medium");
    expect(client.mapOSVSeverity()).toBe("medium");
  });
});
