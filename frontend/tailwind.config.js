module.exports = {
  content: [
    './index.html',
    './src/**/*.{js,jsx,ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        lumina: {
          900: '#0c1222',
          800: '#151e35',
          700: '#1e2d4a',
          600: '#2a3c5e',
          cyan: '#22d3ee',
          indigo: '#818cf8',
          rose: '#fb7185',
        }
      },
      animation: {
        'shimmer': 'shimmer 2s linear infinite',
        'float': 'float 6s ease-in-out infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'reveal': 'reveal 0.8s cubic-bezier(0, 0, 0.2, 1) forwards',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '0.5', filter: 'blur(8px)' },
          '50%': { opacity: '1', filter: 'blur(12px)' },
        },
        reveal: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      },
      boxShadow: {
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.25)',
        'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.5)',
        'glow-indigo': '0 0 20px rgba(129, 140, 248, 0.5)',
      }
    },
  },
  plugins: [],
};
