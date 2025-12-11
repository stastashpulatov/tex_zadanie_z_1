/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'bg-primary': '#0b132b',
                'bg-secondary': '#16213e',
                'border-color': '#1f2f4a',
                'accent': '#4fd1c5',
                'text-primary': '#e6ecf4',
                'text-secondary': '#8fa1c1',
            }
        },
    },
    plugins: [],
}
