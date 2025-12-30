/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                primary: {
                    purple: '#7C3AED',
                    blue: '#3B82F6',
                    white: '#FFFFFF',
                },
                bg: {
                    primary: '#FFFFFF',
                    secondary: '#F9FAFB',
                }
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
            }
        },
    },
    plugins: [],
}
