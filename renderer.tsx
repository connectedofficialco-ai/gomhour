import { jsxRenderer } from 'hono/jsx-renderer'

export const renderer = jsxRenderer(({ children, title = '곰아워', disableZoom }: { children?: any; title?: string; disableZoom?: boolean }) => {
  const viewport = disableZoom ? 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover' : 'width=device-width, initial-scale=1.0, viewport-fit=cover'
  const STYLE_VERSION = '20260422-1'
  return (
    <html lang="ko">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content={viewport} />
        <title>{title}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet" />
        <link href={`/static/style.css?v=${STYLE_VERSION}`} rel="stylesheet" />
      </head>
      <body class="min-h-screen" style="background: var(--app-bg); background-color: var(--app-bg);">
        {children}
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
      </body>
    </html>
  )
})
