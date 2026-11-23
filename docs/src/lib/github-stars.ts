import { REPO } from './release';

// Share one request across all pages rendered during a docs build.
let stars: Promise<number | null> | undefined;

export function githubStars(): Promise<number | null> {
	return stars ??= fetch(`https://api.github.com/repos/${REPO}`, {
		headers: { Accept: 'application/vnd.github+json' },
		signal: AbortSignal.timeout(5000),
	})
		.then(async (res) => {
			if (!res.ok) return null;
			const { stargazers_count: count } = await res.json();
			return Number.isSafeInteger(count) && count >= 0 ? count : null;
		})
		.catch(() => null);
}
