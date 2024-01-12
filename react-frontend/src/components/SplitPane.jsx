import React, { Children, cloneElement, useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";

const SplitPane = (props) => {
  const { direction, children, selector, leftWidthReducer, leftId } = props;
  const dispatch = useDispatch();
  const leftWidth = useSelector(selector);

  const [mouseDownXPos, setMouseDownXPos] = useState(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (document.getElementById(leftId).clientWidth) {
      dispatch(leftWidthReducer(document.getElementById(leftId).clientWidth));
    }
  }, []);

  const onMouseDown = (e) => {
    setMouseDownXPos(e.clientX);
    setDragging(true);
  };

  const onMouseMove = (e) => {
    if (dragging && leftWidth && mouseDownXPos) {
      const newLeftWidth = leftWidth + e.clientX - mouseDownXPos;
      setMouseDownXPos(e.clientX);
      dispatch(leftWidthReducer(newLeftWidth));
    }
  };

  const onMouseUp = () => {
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

  const leftStyle =
    leftWidth !== 0
      ? {
          width: `${leftWidth}px`,
        }
      : {
          width: "30%",
        };

  const enhancedChildren = Children.map(children, (child, index) => {
    switch (index) {
      case 0:
        return cloneElement(child, { style: leftStyle });
      case 1:
        return cloneElement(child, {
          customStyle: direction,
          onMouseDown: onMouseDown,
        });
      case 2:
        return cloneElement(child, { className: "flex-1" });
      default:
        break;
    }
  });

  return (
    <div className="flex h-[35rem] justify-center space-x-3">
      {enhancedChildren}
    </div>
  );
};

export default SplitPane;
