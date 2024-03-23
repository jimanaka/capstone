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
  addArg,
  setArgSubtype,
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
  const availableRegs = useSelector(
    (state) => state.payloadGenerator.availableRegs,
  );
  const payloadHexdump = useSelector(
    (state) => state.payloadGenerator.payloadHexdump,
  );
  const payloadDump = useSelector(
    (state) => state.payloadGenerator.payloadDump,
  );

  const handleAddChainItemPress = () => {
    dispatch(
      addUserChain({
        type: "raw",
        subtype: "hex",
        reg: "",
        args: [],
      }),
    );
  };

  const handleTypeChange = (event, chainNum) => {
    dispatch(
      event.target.value === "padding"
        ? setUserChainIndex({
            index: chainNum,
            chain: {
              type: event.target.value,
              subtype: "padding",
              reg: "",
              args: [],
            },
          })
        : event.target.value === "function"
          ? setUserChainIndex({
              index: chainNum,
              chain: {
                type: event.target.value,
                subtype: "symbol",
                reg: "",
                args: [],
              },
            })
          : setUserChainIndex({
              index: chainNum,
              chain: {
                type: event.target.value,
                subtype: "hex",
                reg: "",
                args: [],
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
  const handleAddArg = (chainNum) => {
    dispatch(
      addArg({
        index: chainNum,
      }),
    );
  };
  const handleArgSubtypeChange = (event, chainNum, argIndex) => {
    dispatch(
      setArgSubtype({
        index: chainNum,
        argIndex: argIndex,
        value: event.target.value,
      }),
    );
  };

  const handleChainSubmit = (data) => {
    data.input.map((item, index) => {
      let argArray = [];
      item.type = userChain[index].type;
      item.subtype = userChain[index].subtype;
      item.reg = userChain[index].reg;
      if (item.args) {
        item.args.map((arg, argIndex) => {
          argArray.push({
            arg: arg,
            subtype: userChain[index].args[argIndex].subtype,
          });
        });
      }
      item.args = argArray;
    });
    dispatch(createPayload(data));
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

  const UserChainItem = ({ chainNum }) => {
    const types = ["raw", "padding", "reg", "function"];
    const subTypes = ["hex", "numeric", "string"];
    const resolvableTypes = ["address", "symbol"];
    return (
      <div className="flex w-full flex-col border border-ctp-surface0 bg-ctp-mantle p-2 shadow-sm">
        <div className="flex w-full items-center justify-between">
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
                items={
                  userChain[chainNum].type === "function"
                    ? resolvableTypes
                    : subTypes
                }
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
              type={
                userChain[chainNum].subtype === "numeric" ? "number" : "text"
              }
              id={`input${chainNum}`}
              placeholder="Value"
              className="input-primary mr-2 w-full min-w-0 resize-x p-2"
              required
              {...register(`input.${chainNum}.value`)}
            />
          )}
        </div>
        {userChain[chainNum].type === "function" ? (
          <>
            {userChain[chainNum].args.map((arg, argIndex) => {
              return (
                <div
                  key={`chain${chainNum}.arg${argIndex}`}
                  className="mt-2 flex"
                >
                  <SelectionMenu
                    chainNum={chainNum}
                    handleChange={(event) =>
                      handleArgSubtypeChange(event, chainNum, argIndex)
                    }
                    items={subTypes}
                    placeholder="subtype"
                    currentVal={userChain[chainNum].args[argIndex].subtype}
                  />

                  <input
                    type={
                      userChain[chainNum].args[argIndex].subtype === "numeric"
                        ? "number"
                        : "text"
                    }
                    id={`input${chainNum}.arg${argIndex}`}
                    placeholder="Value"
                    className="input-primary mr-2 w-full min-w-0 resize-x p-2"
                    required
                    {...register(`input.${chainNum}.args.${argIndex}`)}
                  />
                </div>
              );
            })}
            <button
              type="button"
              className="btn-primary mt-2 inline-flex  items-center justify-center p-1"
              onClick={() => handleAddArg(chainNum)}
            >
              <PlusCircleIcon className="mr-1 h-8 w-8" />
              <span>Add Arg</span>
            </button>
          </>
        ) : null}
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
          <CodeView className="mt-2 flex flex-1 flex-col  overflow-scroll text-left font-mono">
            <Code language="x86asm" highlight={false}>
              {payloadDump}
            </Code>
          </CodeView>
        </div>

        {/* payload hexdump */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Hexdump</h1>
          <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
            <Code language="x86asm" highlight={false}>
              {payloadHexdump}
            </Code>
          </CodeView>
        </div>
      </div>
    </div>
  );
};

export default PayloadGenerator;
