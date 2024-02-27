import React, { useEffect, useState, useRef, createRef } from "react";
import CodeView from "./CodeView";
import DropDown from "./DropDown";
import Code from "./Code";
import {
  getFileInfo,
  disassembleBinary,
  decompileFunction,
} from "../redux/slice/codeListingSlice";
import { useSelector, useDispatch } from "react-redux";

const CodeListing = () => {
  const dispatch = useDispatch();
  const fileInfo = useSelector((state) => state.codeListing.fileInfo);
  const functions = useSelector((state) => state.codeListing.functions);
  const exports = useSelector((state) => state.codeListing.exports);
  const imports = useSelector((state) => state.codeListing.imports);
  const sections = useSelector((state) => state.codeListing.sections);
  const classes = useSelector((state) => state.codeListing.classes);
  // const entry = useSelector((state) => state.codeListing.entry);
  const symbols = useSelector((state) => state.codeListing.symbols);
  const strings = useSelector((state) => state.codeListing.strings);
  const assembly = useSelector((state) => state.codeListing.assembly);
  const oldTopAddress = useSelector((state) => state.codeListing.oldTopAddress);
  const topAddress = useSelector((state) => state.codeListing.topAddress);
  const bottomAddress = useSelector((state) => state.codeListing.bottomAddress);
  const decompiledCode = useSelector(
    (state) => state.codeListing.decompiledCode,
  );

  const [scrollTop, setScrollTop] = useState(null);
  const [scrollBot, setScrollBot] = useState(null);
  const [oldAssemblyHeight, setOldAssemblyHeight] = useState(0);
  const [highlight, setHighlight] = useState("");
  const [noAssemblyScroll, setNoAssemblyScroll] = useState(true);
  const assemblyContainerRef = useRef(null);
  const assemblyListRef = useRef(null);

  const handleAssemblyScroll = (event) => {
    setScrollTop(event.currentTarget.scrollTop);
    setScrollBot(
      event.currentTarget.scrollHeight -
        (event.currentTarget.scrollTop + event.currentTarget.clientHeight),
    );
  };

  useEffect(() => {
    return () => {
      if (assemblyContainerRef.current) {
        assemblyContainerRef.current.scrollTo(0, 0);
      }
    };
  }, []);

  useEffect(() => {
    if (oldAssemblyHeight === 0 || scrollTop !== 0) return;
    if (oldAssemblyHeight !== assemblyListRef.current.clientHeight) {
      assemblyContainerRef.current.scrollTo({
        top: assemblyListRef.current.clientHeight - oldAssemblyHeight,
        behavior: "instant",
      });
    }
  }, [assembly, scrollTop]);

  useEffect(() => {
    if (scrollTop === null || scrollBot === null) return;
    if (noAssemblyScroll) {
      setNoAssemblyScroll(false);
      return
    }
    if (scrollTop === 0) {
      setOldAssemblyHeight(assemblyListRef.current.clientHeight);
      dispatch(
        disassembleBinary({
          filename: "/app/example-bins/hello_world.out",
          direction: "up",
          target: `${topAddress}`,
          mode: "concat",
        }),
      );
    }
    if (scrollBot === 0) {
      dispatch(
        disassembleBinary({
          filename: "/app/example-bins/hello_world.out",
          direction: "down",
          target: `${bottomAddress}`,
          mode: "concat",
        }),
      );
    }
  }, [scrollTop, scrollBot]);

  const handleMetadataClick = (e, address) => {
    setHighlight(address);
    setNoAssemblyScroll(true);
    setOldAssemblyHeight(0);
    dispatch(
      disassembleBinary({
        filename: "/app/example-bins/hello_world.out",
        direction: null,
        target: address,
        mode: "refresh",
      }),
    );
    dispatch(
      decompileFunction({
        filename: "/app/example-bins/hello_world.out",
        address: address,
      }),
    );
    assemblyContainerRef.current.scrollTo({
      top: 0,
      behavior: "instant",
    });
  };

  const handleAssemblyClick = (e, address) => {
    setHighlight(address);
    dispatch(
      decompileFunction({
        filename: "/app/example-bins/hello_world.out",
        address: address,
      }),
    );
  }

  return (
    <div className="pl-4 pr-4 pb-4 w-full h-[50rem]">
      <div className="flex mt-2 h-full w-full justify-ceter space-x-4">
        <div className="flex flex-col w-80 h-full shrink-0">
          <h1 className="w-full text-center">MetaData</h1>
          <div className="h-full w-full overflow-y-scroll">
            <DropDown
              className="mt-2 w-full"
              label="File Info"
              items={fileInfo}
              type="fileInfo"
            />
            <DropDown
              className="mt-2 w-full"
              label="Sections"
              items={sections}
              type="sections"
              handleClick={handleMetadataClick}
            />
            <DropDown
              className="mt-2 w-full"
              label="Functions"
              items={functions}
              type="functions"
              handleClick={handleMetadataClick}
            />
            <DropDown
              className="mt-2 w-full"
              label="Exports"
              items={exports}
              type="exports"
              handleClick={handleMetadataClick}
            />
            <DropDown
              className="mt-2 w-full"
              label="Imports"
              items={imports}
              type="imports"
              handleClick={handleMetadataClick}
            />
            <DropDown
              className="mt-2 w-full"
              label="Classes"
              items={classes}
              type="classes"
            />
            <DropDown
              className="mt-2 w-full"
              label="Symbols"
              items={symbols}
              type="symbols"
              handleClick={handleMetadataClick}
            />
            <DropDown
              className="mt-2 w-full"
              label="Strings"
              items={strings}
              type="strings"
              handleClick={handleMetadataClick}
            />
          </div>
        </div>
        <div className="flex flex-col w-[45rem] h-full shrink-0">
          <h1 className="w-full text-center">Assembly</h1>
          <CodeView className="h-full w-full mt-2 overflow-y-scroll text-left font-mono whitespace-pre">
            <div
              className="h-full w-full overflow-auto"
              onScroll={handleAssemblyScroll}
              ref={assemblyContainerRef}
              id="assemblyList"
            >
              <ul ref={assemblyListRef}>
                {assembly
                  ? assembly.map((line, index) => {
                    let address = `0x${line.offset.toString(16)}`
                    let isHighlighted = address === highlight ? true : false;
                      return (
                        <li
                          key={`assembly:${address}:${index}`}
                          onClick={(e) => handleAssemblyClick(e, address)}
                        >
                          <Code language="x86asm" highlight={isHighlighted}>{line.text}</Code>
                        </li>
                      );
                    })
                  : null}
              </ul>
            </div>
          </CodeView>
        </div>
        <div className="flex flex-col w-[45rem] h-full shrink-0">
          <h1 className="w-full text-center">Decompiled C Code</h1>
          <CodeView className="h-full w-full mt-2 overflow-y-scroll text-left font-mono whitespace-pre">
            <div className="h-full w-full overflow-auto">
              <ul>
                {decompiledCode
                  ? decompiledCode.map((line, index) => {
                      return (
                        <li key={`decompiledCode:${index}`}>
                          <Code language="c">{line}</Code>
                        </li>
                      );
                    })
                  : null}
              </ul>
            </div>
          </CodeView>
        </div>
      </div>
    </div>
  );
};

export default CodeListing;
