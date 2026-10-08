import { describe, it, expect, vi, beforeEach } from 'vitest';

// Referral links (entry_routes) deliver their scenario step 1 only once per
// friend: re-opening the same friend-add URL must not re-send the welcome.
// tracked_links keep the click-campaign re-push (covered by the 60s cooldown).
//
// Drives POST /api/liff/link (already-linked branch) so applyRefAttribution
// runs the scenario-push path against mocked @line-crm/db / line-sdk /
// step-delivery modules.
const pushMessage = vi.fn().mockResolvedValue(undefined);

const dbMocks = {
  // eager module-load deps (mirror liff-offer-attribution.test.ts)
  getLineAccounts: vi.fn().mockResolvedValue([]),
  getStaffByApiKey: vi.fn(),
  recoverStalledBroadcasts: vi.fn(),
  recoverStuckDeliveries: vi.fn(),
  // /api/liff/link + applyRefAttribution helpers
  getFriendByLineUserId: vi.fn(),
  getEntryRouteByRefCode: vi.fn().mockResolvedValue(null),
  getTrackedLinkById: vi.fn().mockResolvedValue(null),
  getAffiliateLinkByRefCode: vi.fn().mockResolvedValue(null),
  getAffiliateOfferById: vi.fn().mockResolvedValue(null),
  getAffiliateById: vi.fn().mockResolvedValue(null),
  addTagToFriend: vi.fn().mockResolvedValue(undefined),
  recordRefTracking: vi.fn().mockResolvedValue(undefined),
  getLineAccountByChannelId: vi.fn().mockResolvedValue(null),
  getLineAccountById: vi.fn().mockResolvedValue(null),
  // scenario push (dynamic import inside applyRefAttribution)
  getScenarioById: vi.fn(),
  getScenarioSteps: vi.fn().mockResolvedValue([]),
  enrollFriendInScenario: vi.fn().mockResolvedValue({ id: 'FS-1', current_step_order: 0 }),
  advanceFriendScenario: vi.fn().mockResolvedValue(undefined),
  completeFriendScenario: vi.fn().mockResolvedValue(undefined),
  getFriendById: vi.fn().mockResolvedValue(null),
  // A time in the past → step 1 counts as "send now".
  computeNextDeliveryAt: vi.fn(() => new Date(0)),
  resolveStepContent: vi.fn().mockResolvedValue({
    messageType: 'text',
    messageContent: 'ようこそ',
    templateIdAtSend: null,
  }),
};
vi.mock('@line-crm/db', () => dbMocks);

vi.mock('@line-crm/line-sdk', () => ({
  LineClient: class {
    pushMessage = pushMessage;
  },
}));

vi.mock('../services/step-delivery.js', () => ({
  buildMessage: (type: string, text: string) => ({ type, text }),
  expandVariables: (text: string) => text,
  resolveMetadata: async () => ({}),
  messageToLogPayload: (m: { type: string; text: string }) => ({
    messageType: m.type,
    content: m.text,
  }),
}));

vi.mock('../services/affiliate-notifier.js', () => ({
  notifyAffiliateFriendAdd: vi.fn().mockResolvedValue(undefined),
}));

const worker = (await import('../index.js')).default;

// messages_log lookups: `everSent` answers the new "ever delivered" check,
// the 60s cooldown query (has `created_at >`) always answers "nothing recent".
let everSent = false;
const DB = {
  prepare: (sql: string) => ({
    bind: () => ({
      run: async () => ({}),
      first: async () => {
        if (sql.includes('FROM messages_log') && !sql.includes('created_at >')) {
          return everSent ? { 1: 1 } : null;
        }
        return null;
      },
      all: async () => ({ results: [] }),
    }),
  }),
} as unknown as D1Database;

const env = {
  DB,
  LIFF_URL: 'https://liff.line.me/1000000000-DefaultAA',
  WORKER_URL: 'https://worker.example.com',
  LINE_LOGIN_CHANNEL_ID: '2000000000',
  LINE_CHANNEL_ACCESS_TOKEN: 'env-token',
} as unknown as import('../index.js').Env['Bindings'];

function link(ref: string) {
  return worker.fetch(
    new Request('https://worker.example.com/api/liff/link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: 'tok', ref }),
    }),
    env,
    { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext,
  );
}

const scenario = {
  id: 'SC-1',
  delivery_mode: 'relative',
  steps: [{ id: 'STEP-1', step_order: 1, delay_minutes: 0, on_reach_tag_id: null }],
};

describe('POST /api/liff/link — referral link welcome is sent once per friend', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    everSent = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url === 'https://api.line.me/oauth2/v2.1/verify') {
          return new Response(JSON.stringify({ sub: 'U-friend', name: 'Tester' }), { status: 200 });
        }
        return new Response('not found', { status: 404 });
      }),
    );
    dbMocks.getFriendByLineUserId.mockResolvedValue({
      id: 'F-1',
      line_account_id: null,
      user_id: 'U-uuid',
    });
    dbMocks.getScenarioById.mockResolvedValue(scenario);
    dbMocks.getEntryRouteByRefCode.mockResolvedValue(null);
    dbMocks.getTrackedLinkById.mockResolvedValue(null);
  });

  it('sends the referral welcome the first time', async () => {
    dbMocks.getEntryRouteByRefCode.mockResolvedValue({
      id: 'ER-1', ref_code: 'hakken-lp', tag_id: null, scenario_id: 'SC-1',
    });

    const res = await link('hakken-lp');
    expect(res.status).toBe(200);
    expect(pushMessage).toHaveBeenCalledTimes(1);
  });

  it('does not re-send the referral welcome when the friend already received it', async () => {
    dbMocks.getEntryRouteByRefCode.mockResolvedValue({
      id: 'ER-1', ref_code: 'hakken-lp', tag_id: null, scenario_id: 'SC-1',
    });
    everSent = true;

    const res = await link('hakken-lp');
    expect(res.status).toBe(200);
    expect(pushMessage).not.toHaveBeenCalled();
  });

  it('keeps re-pushing for tracked links (click campaign)', async () => {
    dbMocks.getTrackedLinkById.mockResolvedValue({
      id: 'TL-1', tag_id: null, scenario_id: 'SC-1', is_active: 1,
    });
    everSent = true;

    const res = await link('TL-1');
    expect(res.status).toBe(200);
    expect(pushMessage).toHaveBeenCalledTimes(1);
  });
});
