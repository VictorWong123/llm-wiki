import { Link, Navigate, Route, Routes } from "react-router-dom";
import { Header } from "./components/Header";
import { SidebarNav } from "./components/SidebarNav";
import { MainPage } from "./pages/MainPage";
import { PreflightPage } from "./pages/PreflightPage";
import { RecentlyAddedPage } from "./pages/RecentlyAddedPage";
import { RegressionTestsPage } from "./pages/RegressionTestsPage";
import { RuleDetailPage } from "./pages/RuleDetailPage";
import { RuleListPage } from "./pages/RuleListPage";
import { SearchResultsPage } from "./pages/SearchResultsPage";
import { SimplePage } from "./pages/SimplePage";
import { ViolationDetailPage } from "./pages/ViolationDetailPage";
import { ViolationsPage } from "./pages/ViolationsPage";

export default function App() {
  return (
    <div className="site-shell">
      <Header />
      <SidebarNav />
      <main className="site-main" id="content">
        <Routes>
          <Route path="/" element={<MainPage />} />
          <Route path="/preflight" element={<PreflightPage />} />
          <Route path="/rules" element={<RuleListPage />} />
          <Route path="/rules/:id" element={<RuleDetailPage />} />
          <Route path="/unsafe-patterns" element={<SimplePage pageId="unsafe-patterns" />} />
          <Route path="/safe-patterns" element={<SimplePage pageId="safe-patterns" />} />
          <Route path="/violations" element={<ViolationsPage />} />
          <Route path="/violations/:id" element={<ViolationDetailPage />} />
          <Route path="/regression-tests" element={<RegressionTestsPage />} />
          <Route path="/recently-added" element={<RecentlyAddedPage />} />
          <Route path="/recent-changes" element={<SimplePage pageId="recent-changes" />} />
          <Route path="/help" element={<SimplePage pageId="help" />} />
          <Route path="/about" element={<SimplePage pageId="about" />} />
          <Route path="/docs" element={<SimplePage pageId="docs" />} />
          <Route path="/contribute" element={<SimplePage pageId="contribute" />} />
          <Route path="/changelog" element={<SimplePage pageId="changelog" />} />
          <Route path="/security" element={<SimplePage pageId="security" />} />
          <Route path="/api" element={<SimplePage pageId="api" />} />
          <Route path="/privacy" element={<SimplePage pageId="privacy" />} />
          <Route path="/terms" element={<SimplePage pageId="terms" />} />
          <Route path="/search" element={<SearchResultsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="site-footer">
        <nav aria-label="Footer links">
          <Link to="/privacy">Privacy Policy</Link>
          <Link to="/terms">Terms of Use</Link>
          <Link to="/security">Security</Link>
          <Link to="/api">API</Link>
        </nav>
        <span>Redline v0.3.1 (build 20250520)</span>
      </footer>
    </div>
  );
}
