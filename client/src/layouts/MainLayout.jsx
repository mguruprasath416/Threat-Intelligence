// ============================================================
// layouts/MainLayout.jsx — WITH MOBILE SIDEBAR TOGGLE
// ============================================================
// On desktop: sidebar always visible
// On mobile:  sidebar hidden, opens via hamburger button
// ============================================================

import { useState, useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Navbar  from '../components/Navbar/Navbar';
import Sidebar from '../components/Sidebar/Sidebar';
import './MainLayout.css';

const MainLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  // Close sidebar on route change (mobile UX)
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  // Close sidebar when clicking outside (overlay)
  const handleOverlayClick = () => {
    setSidebarOpen(false);
  };

  return (
    <div className="app-shell">

      {/* Top navbar with hamburger */}
      <Navbar
        onMenuToggle={() => setSidebarOpen(p => !p)}
        sidebarOpen={sidebarOpen}
      />

      {/* Dark overlay — appears behind sidebar on mobile */}
      <div
        className={`sidebar-overlay ${sidebarOpen ? 'visible' : ''}`}
        onClick={handleOverlayClick}
      />

      {/* Sidebar — slides in on mobile */}
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main content */}
      <main className="main-content">
        <Outlet />
      </main>

    </div>
  );
};

export default MainLayout;