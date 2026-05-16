import { FormEvent, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

export function Header() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get("q") ?? "");

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    navigate(`/search?q=${encodeURIComponent(query.trim())}`);
  }

  return (
    <header className="site-header">
      <div className="brand-block">
        <Link className="brand-link" to="/">Redline</Link>
        <div className="tagline">A living safety wiki for coding agents.</div>
      </div>
      <nav className="top-nav" aria-label="Top navigation">
        <Link to="/">main page</Link>
        <Link to="/recent-changes">recent changes</Link>
        <Link to="/help">help</Link>
      </nav>
      <form className="search-form" role="search" onSubmit={handleSubmit}>
        <label htmlFor="site-search">Search Redline</label>
        <div>
          <input id="site-search" value={query} onChange={(event) => setQuery(event.target.value)} />
          <button type="submit">Search</button>
        </div>
      </form>
    </header>
  );
}
