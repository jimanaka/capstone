import React from "react";
import { useEffect, useState } from "react";
import ConfirmButton from "./ConfirmButton";
import { useDispatch, useSelector } from "react-redux";
import { listFiles } from "../redux/slice/sandboxSlice";
import { PlusCircleIcon } from "@heroicons/react/24/outline";

import { sendCommand } from "../redux/slice/sessionSlice";
import {
  disassembleBinary,
  getFileInfo,
} from "../redux/slice/codeListingSlice";

const FilePicker = ({ handleFileAddPress, setVisible }) => {
  const dispatch = useDispatch();
  const fileList = useSelector((state) => state.sandbox.fileList);
  const user = useSelector((state) => state.auth.user);

  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    dispatch(listFiles());
  }, []);

  const handleFilePress = (filename) => {
    setSelectedFile(filename);
  };

  const handleConfirmClick = () => {
    if (selectedFile) {
      dispatch(
        sendCommand(
          "-file-exec-and-symbols /app/uploads/" + user + "/" + selectedFile,
        ),
      );
      dispatch(
        getFileInfo({ filename: "/app/uploads/" + user + "/" + selectedFile }),
      );
      dispatch(
        disassembleBinary({
          filename: "/app/uploads/" + user + "/" + selectedFile,
          direction: null,
          target: null,
          mode: "concat",
        }),
      );
      setVisible ? setVisible(false) : null;
    }
  };

  return (
    <div>
      <ul>
        <hr className="border-ctp-surface1" />
        {fileList.length > 0
          ? fileList.map((file, index) => {
              return (
                <div key={index}>
                  <li
                    onClick={() => handleFilePress(file)}
                    className="mt-2 mb-2"
                  >
                    <p>{file}</p>
                  </li>
                  <hr className="border-ctp-surface1" />
                </div>
              );
            })
          : null}
      </ul>
      <div className="flex justify-between">
        <button
          className="btn-primary mt-4 inline-flex items-center rounded-lg"
          onClick={handleFileAddPress}
        >
          <PlusCircleIcon className="mr-2 h-8 w-8" />
          <span>Add File</span>
        </button>
        <button
          className="btn-confirm h-10 w-28 mt-4"
          onClick={handleConfirmClick}
        >
          Confirm
        </button>
      </div>
    </div>
  );
};

export default FilePicker;
