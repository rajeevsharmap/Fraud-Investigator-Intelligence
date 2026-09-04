import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { RoleProvider } from './role'
import './styles.css'
import './layout-overrides.css'
import './login-overrides.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode><BrowserRouter><RoleProvider><App /></RoleProvider></BrowserRouter></StrictMode>,
)
