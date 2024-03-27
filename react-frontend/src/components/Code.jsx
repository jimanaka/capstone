import React from "react";
// import "highlight.js/styles/github.css";
import "@catppuccin/highlightjs/css/catppuccin-macchiato.css";
import hljs from "highlight.js";

const Code = ({
  children,
  language,
  line,
  funcName,
  offset,
  bytes,
  highlight,
}) => {
  const html = hljs.highlight(children, { language }).value;
  return (
    <pre className={`${highlight ? "bg-ctp-overlay0" : null} flex px-1`}>
      {funcName && offset ? (
        <div>
          ({funcName}+{offset}){" "}
        </div>
      ) : null}
      {line ? <div>{line} </div> : null}
      {bytes ? <div> {bytes}</div> : null}
      <code
        className="block w-full text-left text-slate-100"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </pre>
  );
};

export default Code;
