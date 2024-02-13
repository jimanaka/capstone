import React from "react";
// import "highlight.js/styles/github.css";
import "@catppuccin/highlightjs/css/catppuccin-macchiato.css"
import hljs from "highlight.js";

const Code = ({ children, language, line, funcName, offset, highlight }) => {
  const html = hljs.highlight(children, { language }).value;
  return (
    <pre className={`${highlight ? "bg-ctp-overlay0" : null} px-1 flex`}>
      {
        (funcName && offset) ?
          <div>({funcName}+{offset})</div> :
        null
      }
      <div>{line}</div>
      <code className="pl-4 text-left block overflow-x-auto text-slate-100" dangerouslySetInnerHTML={{__html: html}} />
    </pre>
  )
}

export default Code;
