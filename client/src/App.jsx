// ============================================================
// App.jsx — ROOT APPLICATION COMPONENT
// ============================================================
// The top-level component that wraps the entire app.
// Sets up:
//   1. BrowserRouter — enables React Router navigation
//   2. AuthProvider  — global authentication state
//   3. IOCProvider   — global IOC / search state
//   4. AppRoutes     — all page routing
//
// Component tree:
//   <BrowserRouter>
//     <AuthProvider>           ← JWT + user session
//       <IOCProvider>          ← IOC search + list state
//         <AppRoutes />        ← page routing
//         <AlertContainer />   ← toast notifications
//       </IOCProvider>
//     </AuthProvider>
//   </BrowserRouter>
// ============================================================

import { BrowserRouter }   from 'react-router-dom';
import { AuthProvider }    from './context/AuthContext';
import { IOCProvider }     from './context/IOCContext';
import AppRoutes           from './routes/AppRoutes';
import './styles/globals.css';

const App = () => (
  <BrowserRouter>
    <AuthProvider>
      <IOCProvider>
        <AppRoutes />
      </IOCProvider>
    </AuthProvider>
  </BrowserRouter>
);

export default App;
