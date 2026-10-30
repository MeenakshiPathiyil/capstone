import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import './index.css'
import { trackInputModality } from './lib/inputModality'

const root = document.getElementById('root')
if (!root) throw new Error('index.html is missing #root')

trackInputModality()

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
