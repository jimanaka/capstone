import React, { useEffect } from "react";
import CodeView from "./CodeView";
import DropDown from "./DropDown";
import { getFileInfo } from "../redux/slice/codeListingSlice";
import { useSelector, useDispatch } from "react-redux";

const CodeListing = () => {
  const dispatch = useDispatch();
  const fileInfo = useSelector((state) => state.codeListing.fileInfo);
  const exports = useSelector((state) => state.codeListing.exports);
  const imports = useSelector((state) => state.codeListing.imports);
  const sections = useSelector((state) => state.codeListing.sections);
  const classes = useSelector((state) => state.codeListing.classes);
  // const entry = useSelector((state) => state.codeListing.entry);
  const symbols = useSelector((state) => state.codeListing.symbols);
  const strings = useSelector((state) => state.codeListing.strings);

  const handleDisassemble = () => {
    dispatch(getFileInfo({ filename: "/app/example-bins/hello_world.out" }));
  };

  return (
    <div className="pl-4 pr-4 pb-4 w-full h-[50rem]">
      <button className="btn-primary" onClick={handleDisassemble} />
      <div className="flex mt-2 h-full w-full justify-ceter space-x-4">
        <div className="flex flex-col w-80 h-full shrink-0">
          <h1 className="w-full text-center">MetaData</h1>
          <div className="h-full w-full overflow-y-scroll">
            <DropDown className="mt-2 w-full" label="File Info" items={fileInfo} type="fileInfo"/>
            <DropDown className="mt-2 w-full" label="Sections" items={sections} type="sections"/>
            <DropDown className="mt-2 w-full" label="Exports" items={exports} type="exports"/>
            <DropDown className="mt-2 w-full" label="Imports" items={imports} type="imports"/>
            <DropDown className="mt-2 w-full" label="Classes" items={classes} type="classes"/>
            <DropDown className="mt-2 w-full" label="Symbols" items={symbols} type="symbols"/>
            <DropDown className="mt-2 w-full" label="Strings" items={strings} type="strings"/>
          </div>
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
