export function ngrams(s: string, n = 3): Set<string> {
    const out = new Set<string>();
    const str = (s || '').toLowerCase();
    if (!str) return out;
    if (str.length <= n) { out.add(str); return out; }
    for (let i = 0; i <= str.length - n; i++) out.add(str.slice(i, i + n));
    return out;
}
