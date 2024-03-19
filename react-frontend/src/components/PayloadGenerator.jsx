import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { PlusCircleIcon } from "@heroicons/react/24/outline";

import { addUserChain, setUserChain } from "../redux/slice/payloadGeneratorSlice";

import CodeView from "./CodeView";
import Code from "./Code";

const PayloadGenerator = () => {
  const dispatch = useDispatch()
  const userChain = useSelector((store) => store.payloadGenerator.userChain);
  const simpleGadgets = useSelector((store) => store.payloadGenerator.simpleGadgets);

  const handleAddChainItemPress = () => {
    dispatch(addUserChain({ item: "test" }))
  }

  const UserChainItem = () => {
    return (
      <div className="h-[4.5rem] w-full rounded bg-ctp-mantle px-4 py-2 shadow-sm">hello</div>
    )
  }

  return (
    <div className="flex max-h-[calc(100vh_-_10rem)] flex-1 justify-center space-x-4 pb-4 pl-4 pr-4">

      {/* payload builder */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <h1 className="w-full text-center">Payload Builder</h1>
        <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
          <ul>
            {
              userChain.length > 0 ? userChain.map((item, index) => {
                return (
                  <li key={index}>
                    <UserChainItem />
                  </li>
                )
              }) : null
            }
          </ul>
          <button
            type="button"
            className="btn-primary mt-2 inline-flex items-center rounded-full w-full justify-center"
            onClick={handleAddChainItemPress}
          >
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Add Paylaod Chain Element</span>
          </button>
        </CodeView>
      </div>

      {/* gadget list */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <h1 className="w-full text-center">Gadgets</h1>
        <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
          <ul>
            {
              simpleGadgets.length > 0 ? simpleGadgets.map((item, index) => {
                return (
                  <li key={index} className="mt-2">
                    <Code language="x86asm" highlight={false}>
                      {`${item.address}: ${item.insns}\n${item.regs}`}
                    </Code>
                  </li>
                )
              }) : null
            }
          </ul>
        </CodeView>
      </div>

      {/* payload print */}
      <div className="flex max-w-md flex-1 flex-col space-y-4">
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Payload Chain</h1>
          <CodeView className="mt-2 flex flex-1 flex-col  overflow-scroll text-left font-mono">
          </CodeView>
        </div>

        {/* payload hexdump */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Hexdump</h1>
          <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
          </CodeView>
        </div>
      </div>

    </div>
  );
};

export default PayloadGenerator;
