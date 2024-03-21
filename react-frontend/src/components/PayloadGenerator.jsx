import React, { useEffect, Fragment } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useForm } from "react-hook-form";
import { Menu, Transition } from "@headlessui/react";
import { PlusCircleIcon } from "@heroicons/react/24/outline";
import { ChevronRightIcon } from "@heroicons/react/20/solid";

import {
  addUserChain,
  setUserChainIndex,
  setUserChainIndexField,
  createPayload,
} from "../redux/slice/payloadGeneratorSlice";

import CodeView from "./CodeView";
import Code from "./Code";

const PayloadGenerator = () => {
  const dispatch = useDispatch();
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
    setValue,
  } = useForm();
  const userChain = useSelector((store) => store.payloadGenerator.userChain);
  const simpleGadgets = useSelector(
    (store) => store.payloadGenerator.simpleGadgets,
  );
  const availableRegs = useSelector((state) => state.payloadGenerator.availableRegs);

  const handleAddChainItemPress = () => {
    dispatch(addUserChain({ type: "", subtype: "", reg: "" }));
  };

  const handleTypeChange = (event, chainNum) => {
    dispatch(
      setUserChainIndex({
        index: chainNum,
        chain: {
          type: event.target.value,
          subtype: "hex",
          reg: "",
        },
      }),
    );
  };
  const handleSubTypeChange = (event, chainNum) => {
    dispatch(
      setUserChainIndexField({
        index: chainNum,
        field: "subtype",
        value: event.target.value,
      }),
    );
  };
  const handleRegChange = (event, chainNum) => {
    dispatch(
      setUserChainIndexField({
        index: chainNum,
        field: "reg",
        value: event.target.value,
      }),
    );
  };

  const handleChainSubmit = (data) => {
    data.input.map((item, index) => {
      item.type = userChain[index].type;
      item.subtype = userChain[index].subtype;
      item.reg = userChain[index].reg;
    });
    dispatch(createPayload(data));
    console.log(data.input)
  };

  const SelectionMenu = ({
    chainNum,
    handleChange,
    items,
    placeholder,
    currentVal,
  }) => {
    return (
      <Menu
        as="div"
        className="mr-2 h-10 w-fit items-center overflow-visible rounded-lg border-2 border-ctp-overlay0 py-2 pl-1 pr-0 hover:border-ctp-mauve ui-open:border-ctp-mauve"
      >
        <div>
          <Menu.Button className="flex w-full items-center justify-between bg-transparent">
            <span>
              {currentVal !== "" && currentVal !== null
                ? currentVal
                : placeholder}
            </span>
            <ChevronRightIcon className="text-ctp-muave h-5 w-5 ui-open:rotate-90 ui-open:transform" />
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
          <Menu.Items className="mt-2 w-fit divide-y divide-ctp-surface1 rounded-md bg-ctp-surface0 p-1 shadow-lg ring-1 ring-black/5 focus:outline-none">
            {items.length > 0
              ? items.map((item, index) => {
                  return (
                    <Menu.Item
                      key={index}
                      className="group flex w-full items-center rounded-md border-none p-2 text-sm font-bold text-ctp-text hover:text-ctp-mauve"
                    >
                      <button
                        type="button"
                        value={item}
                        onClick={(event) => handleChange(event, chainNum)}
                      >
                        {item}
                      </button>
                    </Menu.Item>
                  );
                })
              : null}
          </Menu.Items>
        </Transition>
      </Menu>
    );
  };

  const types = ["raw", "padding", "reg"];
  const rawTypes = ["hex", "numeric", "string"];
  const UserChainItem = ({ chainNum }) => {
    return (
      <div className="flex h-[4rem] w-full items-center justify-between border border-ctp-surface0 bg-ctp-mantle px-2 py-2 shadow-sm">
        <div className="flex">
          {/* chain types selection */}
          <SelectionMenu
            chainNum={chainNum}
            handleChange={handleTypeChange}
            items={types}
            placeholder="Type"
            currentVal={userChain[chainNum].type}
          />
          {userChain[chainNum].type !== "padding" &&
          userChain[chainNum].type !== "" ? (
            <SelectionMenu
              className="mr-2"
              chainNum={chainNum}
              handleChange={handleSubTypeChange}
              items={rawTypes}
              placeholder="Subtype"
              currentVal={userChain[chainNum].subtype}
            />
          ) : null}
          {userChain[chainNum].type === "reg" ? (
            <SelectionMenu
              chainNum={chainNum}
              handleChange={handleRegChange}
              items={availableRegs}
              placeholder="Registers"
              currentVal={userChain[chainNum].reg}
            />
          ) : null}
        </div>
        {userChain[chainNum].type === "padding" ? (
          <div>
            <input
              type="text"
              id={`paddingVal${chainNum}`}
              className="input-primary mr-2 w-14 p-2"
              placeholder="Char"
              required
              maxLength={1}
              {...register(`input.${chainNum}.padding`)}
            />
            <input
              type="number"
              id={`paddingAmount${chainNum}`}
              placeholder="Amount"
              className="input-primary mr-2 w-32 p-2"
              required
              {...register(`input.${chainNum}.paddingAmount`)}
            />
          </div>
        ) : (
          <input
            type={userChain[chainNum].subtype === "numeric" ? "number" : "text"}
            id={`input${chainNum}`}
            placeholder="Value"
            className="input-primary mr-2 w-full min-w-0 resize-x p-2"
            required
            {...register(`input.${chainNum}.value`)}
          />
        )}
      </div>
    );
  };

  return (
    <div className="flex max-h-[calc(100vh_-_10rem)] flex-1 justify-center space-x-4 pb-4 pl-4 pr-4">
      {/* payload builder */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <h1 className="w-full text-center">Payload Builder</h1>
        <CodeView className="mt-2 flex flex-1 overflow-hidden text-left">
          <form
            onSubmit={handleSubmit(handleChainSubmit)}
            className="flex flex-1 flex-col justify-between overflow-scroll"
          >
            <ul className="flex flex-1 flex-col overflow-scroll font-mono">
              {userChain.length > 0
                ? userChain.map((item, index) => {
                    return (
                      <li key={index}>
                        <UserChainItem chainNum={index} />
                      </li>
                    );
                  })
                : null}
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
              <button type="submit" className="btn-confirm mt-2">
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
            {simpleGadgets.length > 0
              ? simpleGadgets.map((item, index) => {
                  return (
                    <li key={index} className="mt-2">
                      <Code language="x86asm" highlight={false}>
                        {`${item.address}: ${item.insns}\n${item.regs}`}
                      </Code>
                    </li>
                  );
                })
              : null}
          </ul>
        </CodeView>
      </div>

      {/* payload print */}
      <div className="flex max-w-md flex-1 flex-col space-y-4">
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Payload Chain</h1>
          <CodeView className="mt-2 flex flex-1 flex-col  overflow-scroll text-left font-mono"></CodeView>
        </div>

        {/* payload hexdump */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Hexdump</h1>
          <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono"></CodeView>
        </div>
      </div>
    </div>
  );
};

export default PayloadGenerator;
