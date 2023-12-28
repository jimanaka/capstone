import React from "react";
import CodeView from "./CodeView";

const Debugger = () => {
  return (
    <div className="m-5 flex h-[35rem] justify-center space-x-4">
      <CodeView>Assembly</CodeView>
      <div className="flex flex-col space-y-4">
        <CodeView>Registers</CodeView>
        <CodeView>Stack</CodeView>
      </div>
      <CodeView>Debugger, breakpoints, etc.</CodeView>
    </div>
  );
};

export default Debugger;
