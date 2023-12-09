import React from "react";

const ResizeSpacer = (props) => {
  const { customStyle, onMouseDown, ...otherProps } = props;
  return (
    <div onMouseDown={onMouseDown} {...otherProps}>
      {customStyle === "vertical" ? (
        <hr className="bg-ctp-surface1 hover:bg-ctp-mauve h-full w-2.5 rounded-xl border-none transition ease-in-out hover:scale-x-150" />
      ) : (
        <hr className="bg-ctp-surface1 hover:bg-ctp-mauve h-1 w-full rounded-xl border-none transition ease-in-out hover:scale-y-150" />
      )}
    </div>
  );
};

export default ResizeSpacer;
