import React from "react";

const DotSpinner = () => {
  return (
    <div className="flex items-center justify-center space-x-2">
      <div className="h-4 w-4 animate-pulse rounded-full bg-violet-600 dark:bg-violet-400"></div>
      <div className="h-4 w-4 animate-pulse rounded-full bg-violet-600 dark:bg-violet-400"></div>
      <div className="h-4 w-4 animate-pulse rounded-full bg-violet-600 dark:bg-violet-400"></div>
    </div>
  );
};

export default DotSpinner;
