const test = require("node:test");
const assert = require("node:assert/strict");
const { DownlinkService, buildDownlinkUrl } = require("../src/services/downlinkService");

function fakeAuthService(token = "access-token") {
  return {
    async getAccessToken() {
      return token;
    }
  };
}

test("downlink service extracts and sorts pending downlinks", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, authorization: options.headers.Authorization, body });

    if (url === "https://api.example.test/lte-connector/get-pending-downlinks") {
      return new Response(JSON.stringify([
        {
          id: "downlink-2",
          createdAt: "2024-04-05T12:00:00.000Z",
          counter: 236,
          payload: "12230000010602"
        },
        {
          id: "downlink-1",
          createdAt: "2024-04-05T11:00:00.000Z",
          counter: 235,
          payload: "12230000010502"
        },
        {
          id: "downlink-3",
          createdAt: "2024-04-05T12:00:00.000Z",
          counter: 235,
          payload: "12230000010702"
        }
      ]), { status: 200 });
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    }, {
      authService: fakeAuthService()
    });

    const pendingDownlinks = await service.getPendingDownlinks("00001111", { battery: 88 });

    assert.deepEqual(pendingDownlinks, [
      {
        payload: "12230000010502",
        id: "downlink-1",
        counter: 235,
        createdAt: "2024-04-05T11:00:00.000Z"
      },
      {
        payload: "12230000010702",
        id: "downlink-3",
        counter: 235,
        createdAt: "2024-04-05T12:00:00.000Z"
      },
      {
        payload: "12230000010602",
        id: "downlink-2",
        counter: 236,
        createdAt: "2024-04-05T12:00:00.000Z"
      }
    ]);

    assert.deepEqual(requests, [
      {
        url: "https://api.example.test/lte-connector/get-pending-downlinks",
        method: "POST",
        authorization: "Bearer access-token",
        body: {
          deviceId: "00001111",
          metadata: { battery: 88 }
        }
      }
    ]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("downlink service treats empty array responses as no pending downlinks", async () => {
  const originalFetch = global.fetch;

  global.fetch = async () => new Response(JSON.stringify([]), { status: 200 });

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    });

    assert.deepEqual(await service.getPendingDownlinks("00001111"), []);
  } finally {
    global.fetch = originalFetch;
  }
});

test("downlink service reconciles active retransmits with the backend", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    requests.push({ url, body: JSON.parse(options.body) });
    return new Response(JSON.stringify({
      retransmits: [
        { counter: 235, action: "cancel", reason: "downlink_cancelled" },
        { counter: 236, action: "continue" }
      ]
    }), { status: 200 });
  };

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    });
    const retransmits = [
      {
        id: "downlink-1",
        counter: 235,
        retriesSent: 12,
        initialSentAt: "2026-09-25T10:00:00.000Z",
        lastSentAt: "2026-09-25T10:15:00.000Z"
      },
      {
        id: null,
        counter: 236,
        retriesSent: 0,
        initialSentAt: "2026-09-25T10:01:00.000Z",
        lastSentAt: "2026-09-25T10:01:00.000Z"
      }
    ];

    assert.deepEqual(await service.reconcileRetransmits("00001111", retransmits), [
      { counter: 235, action: "cancel", reason: "downlink_cancelled" },
      { counter: 236, action: "continue" }
    ]);
    assert.deepEqual(requests, [{
      url: "https://api.example.test/lte-connector/reconcile-downlink-retransmits",
      body: { deviceId: "00001111", retransmits }
    }]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("downlink service rejects pending downlink responses without ordering fields", async () => {
  const responses = [
    [{ id: "downlink-1", createdAt: "2024-04-05T11:00:00.000Z", payload: "12230000010502" }],
    [{ id: "downlink-2", createdAt: "2024-04-05T11:00:00.000Z", counter: null, payload: "12230000010502" }],
    [{ id: "downlink-3", counter: 235, payload: "12230000010502" }],
    ["12230000010502"]
  ];
  const originalFetch = global.fetch;

  global.fetch = async () => {
    const response = responses.shift();
    return new Response(JSON.stringify(response), { status: 200 });
  };

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    });

    await assert.rejects(
      service.getPendingDownlinks("00001111"),
      /Downlink service response must include "counter"/
    );
    await assert.rejects(
      service.getPendingDownlinks("00001111"),
      /Downlink service response must include "counter"/
    );
    await assert.rejects(
      service.getPendingDownlinks("00001111"),
      /Downlink service response must include "createdAt"/
    );
    await assert.rejects(
      service.getPendingDownlinks("00001111"),
      /Downlink service response must include "counter"/
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test("downlink service confirms an acknowledged downlink and returns sorted pending downlinks", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, authorization: options.headers.Authorization, body });

    if (url === "https://api.example.test/lte-connector/confirm-pending-downlink") {
      return new Response(JSON.stringify([
        {
          id: "downlink-3",
          createdAt: "2024-04-05T12:00:00.000Z",
          counter: 237,
          payload: "12230000010702"
        },
        {
          id: "downlink-2",
          createdAt: "2024-04-05T11:00:00.000Z",
          counter: 236,
          payload: "12230000010602"
        }
      ]), { status: 200 });
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    }, {
      authService: fakeAuthService("ack-token")
    });

    const pendingDownlinks = await service.confirmAcknowledgedDownlink("00001111", 235);

    assert.deepEqual(pendingDownlinks, [
      {
        payload: "12230000010602",
        id: "downlink-2",
        counter: 236,
        createdAt: "2024-04-05T11:00:00.000Z"
      },
      {
        payload: "12230000010702",
        id: "downlink-3",
        counter: 237,
        createdAt: "2024-04-05T12:00:00.000Z"
      }
    ]);
    assert.deepEqual(requests, [
      {
        url: "https://api.example.test/lte-connector/confirm-pending-downlink",
        method: "POST",
        authorization: "Bearer ack-token",
        body: {
          deviceId: "00001111",
          counter: 235
        }
      }
    ]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("downlink service marks sent downlinks without expecting pending downlinks", async () => {
  const requests = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, method: options.method, body });

    if (url === "https://api.example.test/lte-connector/mark-downlink-sent") {
      return new Response(JSON.stringify({ accepted: true }), { status: 200 });
    }

    throw new Error(`Unexpected url ${url}`);
  };

  try {
    const service = new DownlinkService({
      enabled: true,
      apiUrl: "https://api.example.test/lte-connector",
      timeoutMs: 5000
    });

    assert.deepEqual(await service.markDownlinkSent("00001111", "downlink-1"), { accepted: true });
    assert.deepEqual(requests, [
      {
        url: "https://api.example.test/lte-connector/mark-downlink-sent",
        method: "POST",
        body: {
          deviceId: "00001111",
          downlink: "downlink-1"
        }
      }
    ]);
  } finally {
    global.fetch = originalFetch;
  }
});

test("buildDownlinkUrl derives downlink endpoint paths from the configured API URL", () => {
  assert.equal(
    buildDownlinkUrl("https://api.example.test/lte-connector", "confirm-pending-downlink"),
    "https://api.example.test/lte-connector/confirm-pending-downlink"
  );
  assert.equal(
    buildDownlinkUrl("https://api.example.test/lte-connector/", "mark-downlink-sent"),
    "https://api.example.test/lte-connector/mark-downlink-sent"
  );
});
