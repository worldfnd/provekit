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
        // Dark wordmark for light mode (ink #2D2D2B), pale brand-ink for dark mode.
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo.svg',
        alt: 'ProveKit',
        replacesTitle: true,
      },
      customCss: ['./src/styles/starlight.css'],
      components: {
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      // Force light as the canonical theme on first visit (brand is light-only).
      // Toggle still works for users who switch.
      head: [
        {
          tag: 'script',
          content: `(()=>{try{if(!localStorage.getItem('starlight-theme'))localStorage.setItem('starlight-theme','light');}catch(e){}})();`,
        },
      ],
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
            { slug: 'concepts/what-is-provekit', label: 'What is ProveKit?' },
            { slug: 'getting-started/installation' },
            { slug: 'getting-started/quickstart' },
            { slug: 'getting-started/tutorial', label: 'Tutorial: prove without revealing' },
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
            { slug: 'reference/starter-template', label: 'Starter templates' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { slug: 'concepts/proving-flow' },
            { slug: 'concepts/designing-circuits', label: 'Designing circuits for ProveKit' },
            { slug: 'concepts/artifact-lifecycle' },
            { slug: 'concepts/security-model' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'cli/overview', label: 'CLI reference' },
            { slug: 'reference/performance' },
            { slug: 'reference/comparison', label: 'How ProveKit compares' },
            { slug: 'reference/examples', label: 'Examples catalog' },
            { slug: 'reference/error-codes', label: 'FFI error codes' },
            { slug: 'reference/faq', label: 'FAQ' },
            { slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Operations',
          items: [
            { slug: 'reference/production-checklist' },
            { slug: 'reference/project-status', label: 'Project status' },
            { slug: 'reference/changelog' },
            { slug: 'troubleshooting/common-errors', label: 'Troubleshooting' },
          ],
        },
      ],
    }),
  ],
});
