import React from "react";
import { Tab } from "@headlessui/react";

import CodeListing from "../components/CodeListing";
import Debugger from "../components/Debugger";

const Sandbox = () => {
  return (
    <>
      <div className="bg-ctp-mantle w-full space-x-4 pl-8 py-4">
      </div>
      <Debugger />
    </>
  );
};

export default Sandbox;
