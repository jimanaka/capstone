import React from "react";
import { useEffect, useState } from "react";
import { PlusCircleIcon, TrashIcon } from "@heroicons/react/24/outline";
import { useDispatch, useSelector } from "react-redux";
import { listFiles, deleteFile, setCurrentFilePath } from "../redux/slice/sandboxSlice";

const FilePicker = ({ handleFileAddPress, setVisible }) => {
  const dispatch = useDispatch();
  const fileList = useSelector((state) => state.sandbox.fileList);
  const user = useSelector((state) => state.auth.user);

  const [selectedFile, setSelectedFile] = useState(null);
  const [highlightLine, setHighlightLine] = useState(null);

  useEffect(() => {
    dispatch(listFiles());

    return () => {
      setSelectedFile(null);
    }
  }, []);

  const handleFilePress = (filename, index) => {
    setSelectedFile(filename);
    setHighlightLine(index);
  };

  const handleDeletePress = (filename) => {
    dispatch(deleteFile({ filename: filename }));
  };

  const handleConfirmClick = () => {
    if (selectedFile) {
      dispatch(setCurrentFilePath("/app/uploads/" + user + "/" + selectedFile));
      setVisible ? setVisible(false) : null;
    }
  };

  return (
    <div>
      <ul>
        <hr className="border-ctp-surface1 mx-1" />
        {fileList.length > 0
          ? fileList.map((file, index) => {
              let highlight = index === highlightLine ? true : false;
              return (
                <div key={index}>
                  <div
                    className={`${
                      highlight ? "bg-ctp-overlay0" : null
                    } flex justify-between items-center rounded-md`}
                    onClick={() => handleFilePress(file, index)}
                  >
                    <li
                      className="mt-2 mb-2 pl-4"
                    >
                      <p>{file}</p>
                    </li>
                    <TrashIcon
                      className="h-8 w-8 text-ctp-red hover:text-red-300 hover:bg-ctp-mantle active:bg-ctp-crust rounded-md p-1"
                      onClick={() => handleDeletePress(file)}
                    />
                  </div>
                  <hr className="border-ctp-surface1 mx-1" />
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
