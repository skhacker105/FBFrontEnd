export function sanitizeAcl(acl: any) {
    const norm: { read: string[]; write: string[] } = { read: [], write: [] };
    if (Array.isArray(acl?.read)) norm.read = Array.from(new Set(acl.read));
    if (Array.isArray(acl?.write)) norm.write = Array.from(new Set(acl.write));
    return norm;
}

export function redactFieldsByRole(doc: any, fieldsPolicy: Record<string, any>, role: string) {
    const out = { ...doc };
    for (const [field, rule] of Object.entries(fieldsPolicy || {})) {
        const allowed = Array.isArray(rule?.read) ? rule.read.includes(role) : true;
        if (!allowed) delete out[field];
    }
    return out;
}
