import React from "react";
import CodeView from "./CodeView";
import { disassembleBinary } from "../redux/slice/codeListingSlice";
import { useDispatch } from "react-redux";

const CodeListing = () => {
  const dispatch = useDispatch();
  const handleDisassemble = () => {
    dispatch(disassembleBinary("/app/example-bins/hello_world.out"))
  }

  return (
    <div className="pl-4 pr-4 pb-4 w-full h-[50rem]">
      <button className="btn-primary" onClick={handleDisassemble}/>
      <div className="flex mt-2 h-full w-full justify-ceter space-x-4">
        <div className="flex flex-col w-2/5 h-full">
          <h1 className="w-full text-center">Functions</h1>
          <CodeView className="h-full w-full mt-2" />
        </div>
        <div className="flex flex-col w-full h-full">
          <h1 className="w-full text-center">Assembly</h1>
          <CodeView className="h-full w-full mt-2" />
        </div>
        <div className="flex flex-col w-full h-full">
          <h1 className="w-full text-center">Decompiled C</h1>
          <CodeView className="h-full w-full mt-2" />
        </div>
      </div>
    </div>
  );
};

export default CodeListing;
