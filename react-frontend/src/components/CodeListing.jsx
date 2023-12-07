import React, { useState, useRef, useEffect } from "react";

import CodeView from "./CodeView";
import ResizeSpacer from "./ResizeSpacer";

const CodeListing = () => {
  const [funcPaneWidth, setFuncPaneWidth] = useState(null);
  const funcPaneRef = useRef();

  const [mouseDownXPos, setMouseDownXPos] = useState(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (funcPaneRef.current) {
      if (!funcPaneWidth) {
        console.log(funcPaneRef);
        setFuncPaneWidth(funcPaneRef.current.clientWidth);
        return;
      }
    }
  }, []);

  const onMouseDown = (e) => {
    console.log("down");
    setMouseDownXPos(e.clientX);
    setDragging(true);
  };

  const onMouseMove = (e) => {
    if (dragging && funcPaneWidth && mouseDownXPos) {
      console.log("moving");
      const newFuncPaneWidth = funcPaneWidth + e.clientX - mouseDownXPos;
      setMouseDownXPos(e.clientX);
      setFuncPaneWidth(newFuncPaneWidth);
    }
  };

  const onMouseUp = () => {
    console.log("up");
    console.log(funcPaneWidth);
    console.log(funcPaneRef.current.clientWidth);
    setDragging(false);
  };

  useEffect(() => {
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  });

  const funcPaneStyle = funcPaneWidth
    ? {
        width: `${funcPaneWidth}px`,
      }
    : null;

  return (
    <div className="p-8">
      <div className="flex flex-col justify-center space-y-3">
        <div className="flex h-[35rem] justify-center space-x-3">
          <CodeView style={funcPaneStyle} ref={funcPaneRef}>
            function listing
          </CodeView>
          <ResizeSpacer customStyle="vertical" onMouseDown={onMouseDown} />
          <CodeView className="flex-1">Disassembly</CodeView>
          {/* <ResizeSpacer customStyle="vertical" />
          <CodeView>Decompilation</CodeView> */}
        </div>
        <ResizeSpacer />
        <CodeView>some other stuff maybe?</CodeView>
      </div>
    </div>
  );
};

export default CodeListing;
