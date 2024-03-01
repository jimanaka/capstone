import React from "react";

const DenyButton = ({ children }) => {
  return (
    <>
      <button
        type="submit" className="bg-ctp-red text-ctp-base w-full rounded-lg
        py-4 hover:bg-red-200" >
          {children}
      </button>
    </>
  );
};

export default DenyButton;
