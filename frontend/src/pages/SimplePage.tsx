import { Link } from "react-router-dom";
import { findSimplePage } from "../data";

interface SimplePageProps {
  pageId: string;
}

export function SimplePage({ pageId }: SimplePageProps) {
  const page = findSimplePage(pageId);

  if (!page) {
    return (
      <>
        <h1>Page not found</h1>
        <p><Link to="/">Return to Main Page</Link></p>
      </>
    );
  }

  return (
    <>
      <h1>{page.title}</h1>
      <p>{page.description}</p>
      {page.sections.map((section) => (
        <section className="wiki-section" key={section.heading}>
          <h2>{section.heading}</h2>
          <p>{section.body}</p>
        </section>
      ))}
    </>
  );
}
