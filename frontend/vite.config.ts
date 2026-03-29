import { defineConfig } from 'vite';

export default defineConfig({
	root: '.',
	build: {
		outDir: 'dist',
		emptyOutDir: true,
	},
	server: {
		proxy: {
			'/auth': 'http://localhost:8080',
			'/test': 'http://localhost:8080',
		},
	},
});
