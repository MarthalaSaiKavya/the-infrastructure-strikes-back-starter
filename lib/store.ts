// In-memory store. Resets on process restart or via POST /api/_admin/reset.
// Blue teams may read from this store but should NOT change its shape.
//
// Naive on purpose: global Maps, no locking, no persistence.

export type User = {
  id: string;
  username: string;
  passwordHash: string; // "scrypt$<salt_hex>$<hash_hex>"
  email: string;
  displayName: string;
  createdAt: string;
};

export type ActionObject = {
  id: string;
  ownerId: string;
  title: string;
  body: string;
  createdAt: string;
};

export type ResetToken = {
  token: string;
  userId: string;
  expiresAt: number; // epoch ms
};

type Store = {
  users: Map<string, User>; // keyed by user id
  usersByUsername: Map<string, string>; // username -> user id
  actions: Map<string, ActionObject>;
  resetTokens: Map<string, ResetToken>; // token -> ResetToken
  // Login attempt counter by username — referenced by auth code for a rate
  // limit that blue teams will notice is missing. Kept here so the store has
  // the hook already wired.
  loginAttempts: Map<string, { count: number; firstAt: number }>;
};

declare global {

  var __ISB_STORE__: Store | undefined;
}

function create(): Store {
  return {
    users: new Map(),
    usersByUsername: new Map(),
    actions: new Map(),
    resetTokens: new Map(),
    loginAttempts: new Map(),
  };
}

export function getStore(): Store {
  if (!globalThis.__ISB_STORE__) {
    globalThis.__ISB_STORE__ = create();
  }
  return globalThis.__ISB_STORE__;
}

export function resetStore(): void {
  globalThis.__ISB_STORE__ = create();
}
