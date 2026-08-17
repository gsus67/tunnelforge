import { cp, mkdir, rm } from 'node:fs/promises';
await rm('dist', { recursive: true, force: true });
await mkdir('dist/static', { recursive: true });
await cp('index.html', 'dist/index.html');
await cp('style.css', 'dist/style.css');
await cp('public/static', 'dist/static', { recursive: true });
