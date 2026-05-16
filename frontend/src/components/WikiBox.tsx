import { ReactNode } from "react";

interface WikiBoxProps {
  title: string;
  children: ReactNode;
}

export function WikiBox({ title, children }: WikiBoxProps) {
  return (
    <section className="wiki-box">
      <h2>{title}</h2>
      {children}
    </section>
  );
}
