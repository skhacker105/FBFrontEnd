import { RolePermissions } from '../types';
import { IndexedDBAbstraction } from '../db/IndexedDBAbstraction';

export function withPermission(db: IndexedDBAbstraction, flag: keyof RolePermissions, fn: (...args: any[]) => any) {
    return async (...args: any[]) => {
        await (db as any)._assertPermission(flag);
        return fn(...args);
    };
}

export const AdminAPI = {
    addDevice: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_DEVICES', (input: any) => db.addOrUpdateDevice(input)),
    setRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (input: any) => db.setRole(input)),
    addCustomRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (role: string, perms: RolePermissions) => db.addCustomRole(role, perms)),
    removeCustomRole: (db: IndexedDBAbstraction) => withPermission(db, 'MANAGE_ROLES', (role: string) => db.removeCustomRole(role)),
};
