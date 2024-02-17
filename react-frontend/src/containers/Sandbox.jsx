import React from "react";
import { useEffect } from "react";
import { Tab } from "@headlessui/react";
import {
  PlayCircleIcon,
  DocumentPlusIcon,
  ChevronRightIcon,
  ChevronDoubleRightIcon,
  StopIcon,
} from "@heroicons/react/24/outline";

import CodeListing from "../components/CodeListing";
import Debugger from "../components/Debugger";
import PayloadGenerator from "../components/PayloadGenerator";

import { setCurrentTab, } from "../redux/slice/sandboxSlice";
import { initSocket, disconnect, sendCommand, setOutput } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";

const Sandbox = () => {
  const dispatch = useDispatch();
  const currentTab = useSelector((state) => state.sandbox.currentTab);
  const isConnected = useSelector((state) => state.session.isConnected);
  const gdbPID = useSelector((state) => state.session.gdbPID);

  useEffect(() => {
    if (!isConnected) {
      dispatch(initSocket());
    }

    return () => {
      if (isConnected) {
        dispatch(disconnect(gdbPID));
      }
    };
  }, [isConnected]);

  //Todo: create global constants for gdbmi commands
  const handleFileLoadPress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(
      sendCommand("-file-exec-and-symbols /app/example-bins/hello_world.out"),
    );
  };
  const handleRunPress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-run"));
    dispatch(setOutput([]));
  };
  const handleNextPress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-next"));
  };
  const handleContinuePress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-continue"));
  };
  const handleTabChange = (index) => {
    dispatch(setCurrentTab(index));
  };

  let component = null;
  switch (currentTab) {
    case 0:
      component = <CodeListing classname="w-full" />;
      break;
    case 1:
      component = <Debugger classname="w-full" />;
      break;
    case 2:
      component = <PayloadGenerator classname="w-full" />;
      break;
    default:
      component = null;
  }

  return (
    <>
      <div className="bg-ctp-mantle w-full space-x-4 py-1 pl-8">
        <Tab.Group onChange={(index) => handleTabChange(index)}>
          <Tab.List className="flex justify-center">
            <Tab className="flex-1">Listing</Tab>
            <Tab className="flex-1">Debugger</Tab>
            <Tab className="flex-1">Payload Generator</Tab>
          </Tab.List>
        </Tab.Group>
      </div>
      <div className="flex mt-2 mr-6 ml-6">
        <button
          onClick={handleFileLoadPress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <DocumentPlusIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="rounded-full text-ctp-green active:text-green-300 active:bg-ctp-crust mr-2"
        >
          <PlayCircleIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="rounded-full text-ctp-red active:text-red-300 active:bg-ctp-crust mr-2"
        >
          <StopIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleNextPress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <ChevronRightIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleContinuePress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <ChevronDoubleRightIcon className="h-6 w-6" />
        </button>
      </div>

      {component}
    </>
  );
};

export default Sandbox;
