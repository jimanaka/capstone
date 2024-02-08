import { React, forwardRef } from "react";
import { twMerge } from "tailwind-merge";

// eslint-disable-next-line react/display-name
const CodeView = forwardRef((props, ref) => {
  const { className, children, ...otherProps } = props;
  return (
    <div
      ref={ref}
      {...otherProps}
      className={twMerge(
        "outline-ctp-green h-full w-full rounded-md p-2 outline outline-2 outline-offset-2 text-center",
        className,
      )}
    >
      {children}
    </div>
  );
});

export default CodeView;
