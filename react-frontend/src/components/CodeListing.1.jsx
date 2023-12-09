import React, { useState, useRef, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { setFuncPaneWidth } from "../redux/slice/codeListingSlice";
import CodeView from "./CodeView";
import ResizeSpacer from "./ResizeSpacer";

export const CodeListing = () => {
  const dispatch = useDispatch();
  const funcPaneWidth = useSelector((state) => state.codeListing.funcPaneWidth);

  const funcPaneRef = useRef();

  const [mouseDownXPos, setMouseDownXPos] = useState(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (funcPaneRef.current) {
      dispatch(setFuncPaneWidth(funcPaneRef.current.clientWidth));
    }
  }, []);

  const onMouseDown = (e) => {
    setMouseDownXPos(e.clientX);
    setDragging(true);
  };

  const onMouseMove = (e) => {
    console.log(dragging, funcPaneWidth, mouseDownXPos);
    if (dragging && funcPaneWidth && mouseDownXPos) {
      const newFuncPaneWidth = funcPaneWidth + e.clientX - mouseDownXPos;
      setMouseDownXPos(e.clientX);
      dispatch(setFuncPaneWidth(newFuncPaneWidth));
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

  const funcPaneStyle = funcPaneWidth !== 0
    ? {
      width: `${funcPaneWidth}px`,
    }
    : {
      width: "30%",
    };

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
