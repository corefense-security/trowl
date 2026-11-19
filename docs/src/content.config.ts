import { defineCollection } from 'astro:content';
import { docsLoader, i18nLoader } from '@astrojs/starlight/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
	// Starlight looks this collection up on every page. en.json holds UI string overrides (none yet).
	i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
};
