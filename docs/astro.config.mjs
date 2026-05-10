import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://docs.provekit.dev',
  publicDir: '../assets',
  integrations: [
    starlight({
      title: 'ProveKit Docs',
      description:
        'Documentation for compiling Noir programs to R1CS, generating WHIR proofs, and integrating ProveKit across native, browser, mobile, service, and recursive-verifier environments.',
      tagline: 'Noir to WHIR proofs, from first proof to production integration.',
      favicon: '/favicon.svg',
      logo: {
        src: './src/assets/logo.svg',
        alt: 'ProveKit',
        replacesTitle: true,
      },
      customCss: ['./src/styles/starlight.css'],
      lastUpdated: true,
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 3,
      },
      editLink: {
        baseUrl: 'https://github.com/worldfnd/provekit/edit/main/docs/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/worldfnd/provekit',
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Overview', link: '/' },
            { slug: 'getting-started/installation' },
            { slug: 'getting-started/quickstart' },
          ],
        },
        {
          label: 'Build and integrate',
          items: [
            { slug: 'e2e/overview' },
            { slug: 'e2e/generate-artifacts' },
            { slug: 'e2e/rust' },
            { slug: 'e2e/js-typescript' },
            { slug: 'e2e/swift' },
            { slug: 'e2e/kotlin' },
            { slug: 'integrations/overview' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { slug: 'concepts/proving-flow' },
            { slug: 'concepts/artifact-lifecycle' },
            { slug: 'concepts/security-model' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'cli/overview' },
            { slug: 'reference/project-status' },
            { slug: 'reference/production-checklist' },
            { slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Troubleshooting',
          items: [{ slug: 'troubleshooting/common-errors' }],
        },
      ],
    }),
  ],
});
