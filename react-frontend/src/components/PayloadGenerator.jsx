import React, { useEffect, Fragment } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useForm } from "react-hook-form";
import { Menu, Transition } from "@headlessui/react";
import { PlusCircleIcon } from "@heroicons/react/24/outline";
import { ChevronRightIcon } from "@heroicons/react/20/solid";

import { addUserChain, setUserChain, setUserChainIndexField } from "../redux/slice/payloadGeneratorSlice";

import CodeView from "./CodeView";
import Code from "./Code";

const PayloadGenerator = () => {
  const dispatch = useDispatch()
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
    setValue,
  } = useForm();
  const userChain = useSelector((store) => store.payloadGenerator.userChain);
  const simpleGadgets = useSelector((store) => store.payloadGenerator.simpleGadgets);

  const handleAddChainItemPress = () => {
    dispatch(addUserChain({ type: "Type" }))
  }

  const handleTypeChange = (event, chainNum) => {
    dispatch(setUserChainIndexField({ index: chainNum, field: "type", value: event.target.value }))
  }

  useEffect(() => {
    console.log(userChain);
  }, [userChain]);

  const handleChainSubmit = (data) => {
    console.log(data);
  }

  const SelectionMenu = ({ chainNum, handleChange, items, placeholder }) => {
    return (
      <Menu as="div" className="h-6 overflow-visible">
        <div>
          <Menu.Button className="flex bg-transparent">
            <span>{userChain.length > 0 ? userChain[chainNum].type : placeholder}</span>
            <ChevronRightIcon
              className="text-ctp-muave h-6 w-6 ui-open:rotate-90 ui-open:transform"
            />
          </Menu.Button>
        </div>
        <Transition
          as={Fragment}
          enter="transition duration-100 ease-out"
          enterFrom="scale-95 transform opacity-0"
          enterTo="scale-100 transform opacity-100"
          leave="transition duration-75 ease-in"
          leaveFrom="scale-100 transform opacity-100"
          leaveTo="scale-95 transform opacity-0"
        >
          <Menu.Items className="mt-2 w-fit divide-y divide-ctp-surface1 rounded-md bg-ctp-surface0 shadow-lg ring-1 ring-black/5 focus:outline-none">
            {
              items.length > 0 ? items.map((item, index) => {
                return (
                  <Menu.Item
                    key={index}
                    className="group flex w-full items-center rounded-md p-2 text-sm font-bold text-ctp-text hover:bg-ctp-mauve hover:text-ctp-base"
                  >
                    <button type="button" value={item} onClick={(event) => handleChange(event, chainNum)}>{item}</button>
                  </Menu.Item>
                )
              }) : null
            }
          </Menu.Items>
        </Transition>
      </Menu>
    )
  }

  const types = ["raw", "set reg"]
  const rawTypes = ["hex", "numeric", "string"]
  const UserChainItem = ({ chainNum }) => {
    return (
      <div className="flex h-[4rem] w-full items-center rounded border border-ctp-surface0 bg-ctp-mantle px-4 py-2 shadow-sm">
        {/* chain types selection */}
        <SelectionMenu chainNum={chainNum} handleChange={handleTypeChange} items={types} placeholder="Type" />

        {
          userChain[chainNum].type === "raw" ? (
            < SelectionMenu chainNum={chainNum} handleChange={handleTypeChange} items={rawTypes} placeholder="Type" />
          ) : userChain[chainNum].type === "set reg" ? (
            <SelectionMenu chainNum={chainNum} handleChange={handleTypeChange} items={types} placeholder="Type" />
          ) : null
        }
      </div>
    )
  }

  return (
    <div className="flex max-h-[calc(100vh_-_10rem)] flex-1 justify-center space-x-4 pb-4 pl-4 pr-4">

      {/* payload builder */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <h1 className="w-full text-center">Payload Builder</h1>
        <CodeView className="mt-2 flex flex-1 overflow-hidden text-left">
          <form onSubmit={handleSubmit(handleChainSubmit)} className="flex flex-1 flex-col justify-between overflow-scroll">
            <ul className="flex flex-1 flex-col overflow-scroll font-mono">
              {
                userChain.length > 0 ? userChain.map((item, index) => {
                  return (
                    <li key={index}>
                      <UserChainItem chainNum={index} />
                    </li>
                  )
                }) : null
              }
            </ul>
            <div className="flex justify-between">
              <button
                type="button"
                className="btn-primary mt-2 inline-flex  items-center justify-center"
                onClick={handleAddChainItemPress}
              >
                <PlusCircleIcon className="mr-1 h-8 w-8" />
                <span>Add Link</span>
              </button>
              <button
                type="submit"
                className="btn-confirm mt-2"
              >
                Create Chain
              </button>
            </div>
          </form>
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
