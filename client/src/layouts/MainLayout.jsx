// ============================================================
// layouts/MainLayout.jsx — AUTHENTICATED APP SHELL
// ============================================================
// Wraps all authenticated pages with Navbar + Sidebar.
// The main content area sits to the right of the sidebar,
// below the navbar.
//
// Layout structure:
//   <Navbar />                     ← fixed top bar (60px)
//   <Sidebar />                    ← fixed left sidebar (240px)
//   <main className="content">     ← scrollable content area
//     <Outlet />                   ← current page renders here
//   </main>
// ============================================================

import { Outlet } from 'react-router-dom';
import Navbar     from '../components/Navbar/Navbar';
import Sidebar    from '../components/Sidebar/Sidebar';
import './MainLayout.css';

const MainLayout = () => (
  <div className="app-shell">
    <Navbar />
    <Sidebar />
    <main className="main-content">
      <Outlet />
    </main>
  </div>
);

export default MainLayout;
