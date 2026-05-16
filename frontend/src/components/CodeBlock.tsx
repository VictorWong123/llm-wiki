interface CodeBlockProps {
  code: string;
  language?: string;
}

export function CodeBlock({ code, language = "text" }: CodeBlockProps) {
  const lines = code.split(/\r?\n/);
  return (
    <pre className="code-block" aria-label={`${language} code`}>
      {lines.map((line, index) => (
        <span className="code-line" key={`${index}-${line}`}>
          <span className="line-number">{index + 1}</span>
          <code>{line || " "}</code>
        </span>
      ))}
    </pre>
  );
}
