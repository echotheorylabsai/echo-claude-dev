import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'en-US',
  title: 'secure-claude',
  description: 'Governance, audit, and tool-gating hooks for Claude Code',
  base: '/echo-claude-dev/',
  lastUpdated: true,
  cleanUrls: true,
  ignoreDeadLinks: true,
  head: [
    ['meta', { name: 'theme-color', content: '#1a56db' }],
    ['meta', { property: 'og:title', content: 'secure-claude' }],
    ['meta', { property: 'og:description', content: 'Governance, audit, and tool-gating hooks for Claude Code' }],
  ],
  markdown: {
    theme: { light: 'github-light', dark: 'github-dark' },
    lineNumbers: false,
  },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Reference', link: '/reference/hooks' },
      { text: 'GitHub', link: 'https://github.com/echotheorylabsai/echo-claude-dev' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is secure-claude?', link: '/guide/getting-started' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Architecture', link: '/guide/architecture' },
          ],
        },
        {
          text: 'Usage',
          items: [
            { text: 'Dashboard', link: '/guide/dashboard' },
            { text: 'Customizing Rules', link: '/guide/customizing-rules' },
            { text: 'Disabling Governance', link: '/guide/disable' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'Hooks', link: '/reference/hooks' },
            { text: 'JSONL Schema', link: '/reference/schema' },
            { text: 'Simulator', link: '/reference/simulator' },
            { text: 'Security Model', link: '/reference/security' },
          ],
        },
      ],
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/echotheorylabsai/echo-claude-dev' },
    ],
    search: { provider: 'local' },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Echo Theory Labs',
    },
    editLink: {
      pattern: 'https://github.com/echotheorylabsai/echo-claude-dev/edit/main/docs-site/:path',
      text: 'Edit this page on GitHub',
    },
  },
})
