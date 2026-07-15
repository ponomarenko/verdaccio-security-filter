import { OSVClient } from "../src/lib/osv-client";

jest.setTimeout(120000);

const parseRequestBody = (body: BodyInit | null | undefined): Record<string, unknown> => {
  if (typeof body !== "string") {
    throw new Error("Expected OSV request body to be a JSON string");
  }

  return JSON.parse(body);
};

describe("OSV live integration", () => {
  it("returns no vulnerabilities for a package with no OSV records", async () => {
    const client = new OSVClient({
      timeoutMs: 30000,
    });
    const vulnerabilities = await client.fetchVulnerabilities("left-pad");

    expect(vulnerabilities).toEqual([]);
  });

  it("returns OSV vulnerabilities for an affected package version", async () => {
    const client = new OSVClient({
      timeoutMs: 30000,
    });
    const vulnerabilities = await client.fetchVulnerabilities("lodash");
    const matchingVulnerabilities = vulnerabilities
      .map(vulnerability => client.matchVulnerabilityForVersion(
        vulnerability,
        "lodash",
        "4.17.20",
      ))
      .filter(vulnerability => vulnerability !== undefined);

    expect(vulnerabilities.length).toBeGreaterThan(0);
    expect(matchingVulnerabilities.length).toBeGreaterThan(0);
    expect(matchingVulnerabilities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: expect.any(String),
          source: "osv",
        }),
      ]),
    );
  });

  it("follows real OSV pagination when advisories span multiple pages", async () => {
    const requestBodies: Array<Record<string, unknown>> = [];
    const liveFetch: typeof fetch = jest.fn(async (input, init) => {
      requestBodies.push(parseRequestBody(init?.body));

      const response = await fetch(input, init);
      if (requestBodies.length < 2 || !response.ok) {
        return response;
      }

      const data = await response.json();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { next_page_token: _nextPageToken, ...boundedPage } = data;

      return new Response(JSON.stringify(boundedPage), {
        status: response.status,
        statusText: response.statusText,
        headers: {
          "content-type": "application/json",
        },
      });
    }) as typeof fetch;

    const client = new OSVClient({
      ecosystem: "Linux",
      fetchImpl: liveFetch,
      timeoutMs: 30000,
    });
    const vulnerabilities = await client.fetchVulnerabilities("Kernel");

    expect(liveFetch).toHaveBeenCalledTimes(2);
    expect(requestBodies[0]).toEqual({
      package: {
        name: "Kernel",
        ecosystem: "Linux",
      },
    });
    expect(requestBodies[1]).toEqual({
      package: {
        name: "Kernel",
        ecosystem: "Linux",
      },
      page_token: expect.any(String),
    });
    expect(vulnerabilities.length).toBeGreaterThan(1000);
    expect(vulnerabilities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: expect.any(String),
          source: "osv",
        }),
      ]),
    );
  });
});
