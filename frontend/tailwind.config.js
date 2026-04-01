 /** @type {import('tailwindcss').Config} */
 export default {
   content: ["./index.html", "./src/**/*.{ts,tsx}"],
   theme: {
     extend: {
       colors: {
         bg: "#0b1020",
         panel: "#111a33",
         panel2: "#0f1730",
         text: "#e6e9f2",
         muted: "#a7b0c5",
         accent: "#7c5cff",
         danger: "#ff4d6d",
         warn: "#ffb020",
         ok: "#2dd4bf"
       }
     }
   },
   plugins: []
 };
 
