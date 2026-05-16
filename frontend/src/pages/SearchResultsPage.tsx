import { Link, useSearchParams } from "react-router-dom";
import { searchRedline } from "../search";

export function SearchResultsPage() {
  const [params] = useSearchParams();
  const query = params.get("q") ?? "";
  const results = searchRedline(query);

  return (
    <>
      <h1>Search results</h1>
      <p>Query: {query || "(empty)"}</p>
      {!query.trim() ? <p>Enter a search term.</p> : null}
      {query.trim() && results.length === 0 ? <p>No matching Redline pages found.</p> : null}
      {results.length > 0 ? (
        <ol className="search-results">
          {results.map((result) => (
            <li key={`${result.path}-${result.id}`}>
              <Link to={result.path}>{result.title}</Link>
              <div className="result-path">{result.path}</div>
              <p>{result.snippet}</p>
            </li>
          ))}
        </ol>
      ) : null}
    </>
  );
}
