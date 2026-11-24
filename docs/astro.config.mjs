// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Served from GitHub Pages on the custom domain set in the repo's Pages settings.
export default defineConfig({
	site: 'https://trowl.dev',
	prefetch: {
		prefetchAll: true,
		defaultStrategy: 'viewport',
	},
	redirects: {
		'/reference/network-cache/': '/reference/architecture/#network-and-cache',
	},
	integrations: [
		starlight({
			title: 'Trowl',
			description: 'Trowl is an open-source, post-build security scanner for embedded Linux images. It finds hardening gaps, known CVEs and SBOM discrepancies in Yocto images.',
			logo: {
				light: './src/assets/trowl-logo.svg',
				dark: './src/assets/trowl-logo-dark.svg',
				replacesTitle: true,
			},
			favicon: '/favicon.svg',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/corefense-security/trowl' },
			],
			editLink: {
				baseUrl: 'https://github.com/corefense-security/trowl/edit/main/docs/',
			},
			customCss: ['@fontsource/jetbrains-mono/400.css', '@fontsource/jetbrains-mono/500.css', './src/styles/custom.css'],
			components: {
				Footer: './src/components/Footer.astro',
				Header: './src/components/Header.astro',
				Hero: './src/components/Hero.astro',
				Pagination: './src/components/Pagination.astro',
				SocialIcons: './src/components/SocialIcons.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
			},
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ slug: 'getting-started/docker' },
						{ slug: 'getting-started/install-script' },
					],
				},
				{
					label: 'Integrations',
					items: [{ slug: 'integrations/yocto' }],
				},
				{
					label: 'Capabilities',
					items: [
						{ slug: 'features/hardening' },
						{ slug: 'features/sbom' },
						{ slug: 'features/cves-vex' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ slug: 'reference/supported-targets' },
						{ slug: 'reference/cli' },
						{ slug: 'reference/report' },
						{ slug: 'reference/architecture' },
					],
				},
			],
		}),
	],
});
