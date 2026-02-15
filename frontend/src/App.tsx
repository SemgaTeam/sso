import { Link, Navigate, Route, Routes } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";

function App() {
  return (
    <div className="app">
      <header className="header">
        <h1>SSO Frontend</h1>
        <nav className="nav">
          <Link to="/login">Login</Link>
          <Link to="/register">Register</Link>
        </nav>
      </header>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
