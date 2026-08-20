// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  integrations: [
    starlight({
      title: 'Code Buster',
      description: 'Multi-language repository architecture and static-analysis CLI.',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/tool-bunker/code-buster',
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Overview', slug: 'index' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quickstart', slug: 'getting-started/quickstart' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Configuration', slug: 'guides/configuration' },
            { label: 'Analysis workflows', slug: 'guides/workflows' },
            { label: 'CI and integrations', slug: 'guides/integrations' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Commands', slug: 'reference/commands' },
            { label: 'Reports', slug: 'reference/reports' },
            { label: 'Language support', slug: 'reference/languages' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Contributing', slug: 'project/contributing' },
            { label: 'Security and releases', slug: 'project/security-releases' },
          ],
        },
      ],
    }),
  ],
});
