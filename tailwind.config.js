
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      textColor: {
        'primary': '#6D758D',
        'secondary': '#333742'
      },
      borderColor: {
        'primary': '#6D758D'
      },
      colors: {
        'primary': '#6D758D'
      }
    },
  },
  plugins: [
  ],
}

