// The newest Trowl tag, for the release badge on the landing page.
//
// The build asks the GitHub API once and bakes the answer into the page, so the badge works
// without JavaScript. The page then asks again in the browser, so a tag pushed after the last
// docs build still shows up. FALLBACK is used when the build has no network.

export const REPO = 'corefense-security/trowl';
export const FALLBACK = 'v0.1.0-preview.4';

// vMAJOR.MINOR.PATCH with an optional -preview.N, as compared numbers. Other tags are skipped.
export function parse(tag: string): number[] | null {
	const m = /^v(\d+)\.(\d+)\.(\d+)(?:-preview\.(\d+))?$/.exec(tag);
	if (!m) return null;
	// A stable release sorts after all of its previews.
	return [+m[1], +m[2], +m[3], m[4] === undefined ? Infinity : +m[4]];
}

function compare(a: number[], b: number[]): number {
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
	return 0;
}

export function newest(tags: string[]): string | null {
	let best: string | null = null;
	let bestKey: number[] = [];
	for (const t of tags) {
		const k = parse(t);
		if (k && (best === null || compare(k, bestKey) > 0)) {
			best = t;
			bestKey = k;
		}
	}
	return best;
}

export async function latestTag(): Promise<string> {
	try {
		const res = await fetch(`https://api.github.com/repos/${REPO}/tags?per_page=100`, {
			headers: { Accept: 'application/vnd.github+json' },
			signal: AbortSignal.timeout(5000),
		});
		if (!res.ok) return FALLBACK;
		const tags: { name: string }[] = await res.json();
		return newest(tags.map((t) => t.name)) ?? FALLBACK;
	} catch {
		return FALLBACK;
	}
}
