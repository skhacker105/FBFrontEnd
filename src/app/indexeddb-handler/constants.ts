export const ROLES = Object.freeze({
    CREATOR: 'creator',
    ADMIN: 'admin',
    EDITOR: 'editor',
    VIEWER: 'viewer',
    SYNC_AGENT: 'sync_agent'
} as const);

export const DEFAULT_ROLE_PERMISSIONS = Object.freeze({
    [ROLES.CREATOR]: { READ: true, WRITE: true, DELETE: true, MANAGE_ROLES: true, MANAGE_DEVICES: true, MANAGE_SCHEMA: true },
    [ROLES.ADMIN]: { READ: true, WRITE: true, DELETE: true, MANAGE_ROLES: true, MANAGE_DEVICES: true, MANAGE_SCHEMA: false },
    [ROLES.EDITOR]: { READ: true, WRITE: true, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false },
    [ROLES.VIEWER]: { READ: true, WRITE: false, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false },
    [ROLES.SYNC_AGENT]: { READ: true, WRITE: true, DELETE: false, MANAGE_ROLES: false, MANAGE_DEVICES: false, MANAGE_SCHEMA: false }
} as const);
