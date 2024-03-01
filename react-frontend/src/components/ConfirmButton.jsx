import React from "react";

const ConfirmButton = ({ children }) => {
  return (
    <>
      <button
        type="submit" className="bg-ctp-green text-ctp-base w-full rounded-lg
        py-4 hover:bg-lime-200" >
          {children}
      </button>
    </>
  );
};

export default ConfirmButton;
