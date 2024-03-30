import React from "react";
import { useEffect, useState } from "react";
import { useForm, FormProvider } from "react-hook-form";
import { Tab } from "@headlessui/react";
import {
  PlayCircleIcon,
  DocumentPlusIcon,
  ChevronRightIcon,
  ChevronDoubleRightIcon,
  StopIcon,
  Bars3Icon,
} from "@heroicons/react/24/outline";
import { useDispatch, useSelector } from "react-redux";

import CodeListing from "../components/CodeListing";
import Debugger from "../components/Debugger";
import PayloadGenerator from "../components/PayloadGenerator";
import Modal from "../components/Modal";
import FileDropper from "../components/FileDropper";
import FileCoursePicker from "../components/FileCoursePicker";
import CourseDrawer from "../components/CourseDrawer";

import {
  resetSandboxState,
  setCurrentTab,
  uploadFile,
} from "../redux/slice/sandboxSlice";
import {
  initSocket,
  disconnect,
  setOutput,
  sendCommand,
} from "../redux/slice/sessionSlice";
import {
  disassembleBinary,
  getFileInfo,
  resetCodeListingState,
} from "../redux/slice/codeListingSlice";
import {
  usePayload,
  resetPayloadGeneratorState,
  startPG,
} from "../redux/slice/payloadGeneratorSlice";

const Sandbox = () => {
  const dispatch = useDispatch();
  const currentTab = useSelector((state) => state.sandbox.currentTab);
  const isConnected = useSelector((state) => state.session.isConnected);
  const gdbPID = useSelector((state) => state.session.gdbPID);
  const currentFilePath = useSelector((state) => state.sandbox.currentFilePath);
  const methods = useForm();
  const { handleSubmit, setValue } = methods;

  const [fileDropperOpen, setFileDropperOpen] = useState(false);
  const [fileTextDropperOpen, setFileTextDropperOpen] = useState(false);
  const [filePickerOpen, setFilePickerOpen] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [fileConfirmOpen, setFileConfirmOpen] = useState(false);
  const [selectedFile, setSelectedFile] = React.useState(null);
  const [selectedTextFile, setSelectedTextFile] = React.useState(null);

  useEffect(() => {
    setFilePickerOpen(true);

    return () => {
      dispatch(resetPayloadGeneratorState());
      dispatch(resetCodeListingState());
      dispatch(resetSandboxState());
    };
  }, []);

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

  useEffect(() => {
    if (currentFilePath) {
      let lastSlashIndex = currentFilePath.lastIndexOf("/");
      if (lastSlashIndex !== -1) {
        let workingDir = currentFilePath.substring(0, lastSlashIndex + 1);
        dispatch(sendCommand("-environment-cd " + `\"${workingDir}\"`));
      }
      dispatch(
        sendCommand("-file-exec-and-symbols " + `\"${currentFilePath}\"`),
      );
      dispatch(getFileInfo({ filename: currentFilePath }));
      dispatch(setOutput([]));
      dispatch(
        disassembleBinary({
          filename: currentFilePath,
          direction: null,
          target: null,
          mode: "refresh",
        }),
      );
      dispatch(startPG({ filePath: currentFilePath }));
    }
  }, [currentFilePath]);

  //Todo: create global constants for gdbmi commands
  const handleFileLoadPress = () => {
    setFilePickerOpen(true);
  };
  const handleFileAddPress = () => {
    setFileDropperOpen(true);
  };
  const handleRunPress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-run"));
    dispatch(setOutput([]));
  };
  const handleNextPress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-next-instruction"));
  };
  const handleContinuePress = () => {
    if (currentTab !== 1) dispatch(setCurrentTab(1));
    dispatch(sendCommand("-exec-continue"));
  };
  const handleTabChange = (index) => {
    dispatch(setCurrentTab(index));
  };
  const handleUsePayloadPress = () => {
    dispatch(setOutput([]));
    dispatch(usePayload({ pid: gdbPID }));
  };

  const onCancelClick = () => {
    setFileConfirmOpen(false);
    setFileDropperOpen(true);
  };

  const onCancelTextClick = () => {
    setValue("fileText", null);
    setSelectedTextFile(null);
    setFileTextDropperOpen(false);
    setFileConfirmOpen(true);
  };

  const onConfirmClick = () => {
    setFileDropperOpen(false);
    setFileTextDropperOpen(true);
  };

  const onConfirmTextClick = () => {
    setFileTextDropperOpen(false);
    setFileConfirmOpen(true);
  };

  const onSubmit = (data) => {
    data.fileBinary = data.fileBinary[0];
    if (data.fileText) {
      data.fileText = data.fileText[0];
    } else {
      data.fileText = null;
    }
    dispatch(uploadFile(data));
    setFileDropperOpen(false);
    setFilePickerOpen(true);
  };

  let component = null;
  switch (currentTab) {
    case 0:
      component = <CodeListing />;
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
      <CourseDrawer
        title="Test"
        description="test"
        isOpen={drawerOpen}
        setIsOpen={setDrawerOpen}
      >
        <div>this is a test!!</div>
      </CourseDrawer>
      <Modal
        title="Available Files and Courses"
        isOpen={filePickerOpen}
        closeModal={() => setFilePickerOpen(false)}
      >
        <FileCoursePicker
          handleFileAddPress={handleFileAddPress}
          setVisible={setFilePickerOpen}
        />
      </Modal>
      <FormProvider {...methods}>
        <form id="file-form" onSubmit={handleSubmit(onSubmit)}>
          <Modal
            title="Upload binary"
            isOpen={fileDropperOpen}
            closeModal={() => setFileDropperOpen(false)}
          >
            <FileDropper
              onConfirmClick={onConfirmClick}
              setSelectedFile={setSelectedFile}
              selectedFile={selectedFile}
              registerName="fileBinary"
            />
          </Modal>
          {/* text file upload */}
          <Modal
            title="Upload text file (optional)"
            isOpen={fileTextDropperOpen}
            closeModal={() => setFileTextDropperOpen(false)}
          >
            <FileDropper
              onConfirmClick={onConfirmTextClick}
              onCancelClick={onCancelTextClick}
              setSelectedFile={setSelectedTextFile}
              selectedFile={selectedTextFile}
              registerName="fileText"
            />
          </Modal>
          <Modal
            title={`Upload ${
              selectedFile
                ? selectedTextFile
                  ? selectedFile.name + " and " + selectedTextFile.name
                  : selectedFile.name
                : null
            }?`}
            isOpen={fileConfirmOpen}
            closeModal={() => setFileConfirmOpen(false)}
          >
            <div className="flex w-full space-x-2">
              <button
                type="reset"
                className="mt-2 w-full rounded-lg bg-ctp-red py-4 text-ctp-base hover:bg-red-200"
                onClick={onCancelClick}
              >
                Cancel
              </button>
              <button
                type="submit"
                form="file-form"
                className="mt-2 w-full rounded-lg bg-ctp-green py-4 text-ctp-base hover:bg-lime-200"
                onClick={() => setFileConfirmOpen(false)}
              >
                Confirm
              </button>
            </div>
          </Modal>
        </form>
      </FormProvider>
      <div className="w-full space-x-4 bg-ctp-mantle py-1 px-2 ">
        <Tab.Group onChange={(index) => handleTabChange(index)} className="h-6">
          <Tab.List className="flex justify-center">
            <Tab className="flex-1">Listing</Tab>
            <Tab className="flex-1">Debugger</Tab>
            <Tab className="flex-1">Payload Generator</Tab>
          </Tab.List>
        </Tab.Group>
      </div>
      <div className="ml-6 mr-6 mt-2 flex">
        <button
          onClick={() => setDrawerOpen(true)}
          className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
        >
          <Bars3Icon className="h-6 w-6" />
        </button>
        <button
          onClick={handleFileLoadPress}
          className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
        >
          <DocumentPlusIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="mr-2 rounded-full text-ctp-green active:bg-ctp-crust active:text-green-300"
        >
          <PlayCircleIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="mr-2 rounded-full text-ctp-red active:bg-ctp-crust active:text-red-300"
        >
          <StopIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleNextPress}
          className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
        >
          <ChevronRightIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleContinuePress}
          className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
        >
          <ChevronDoubleRightIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleUsePayloadPress}
          className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
        >
          TEST
        </button>
      </div>

      {component}
    </>
  );
};

export default Sandbox;
