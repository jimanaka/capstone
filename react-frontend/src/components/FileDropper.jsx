import React, { useEffect } from "react";
import { useDropzone } from "react-dropzone";
import { useFormContext } from "react-hook-form";
import {
  CloudArrowUpIcon,
  DocumentCheckIcon,
} from "@heroicons/react/24/outline";

const FileDropper = ({ onConfirmClick, onCancelClick, setSelectedFile, selectedFile, confirm }) => {
  const { register, errors, handleSubmit, control, setValue } =
    useFormContext();
  const { acceptedFiles, getRootProps, getInputProps } = useDropzone({
    onDrop: (files) => {
      setValue("file", files);
    },
  });

  useEffect(() => {
    register("file");
  }, []);

  useEffect(() => {
    setSelectedFile(acceptedFiles[0]);
  }, [acceptedFiles]);

  const handleCancelClick = onCancelClick ? onCancelClick : () => {
    setSelectedFile(null);
    setValue("file", null);
  };

  return (
    <div>
      <div
        {...getRootProps({
          className: "dropzone",
        })}
      >
        <label
          htmlFor="dropzone-file"
          className="flex flex-col items-center justify-center w-full h-64 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-gray-50 dark:hover:bg-bray-800 dark:bg-gray-700 hover:bg-gray-100 dark:border-gray-600 dark:hover:border-gray-500 dark:hover:bg-gray-600"
        >
          {selectedFile ? (
            <div className="flex flex-col items-center justify-center pt-5 pb-6">
              <DocumentCheckIcon className="w-24 h-24 mb-4 text-gray-500 dark:text-gray-400" />
              <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                {selectedFile.name}
              </p>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center pt-5 pb-6">
              <CloudArrowUpIcon className="w-24 h-24 mb-4 text-gray-500 dark:text-gray-400" />
              <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                <span className="font-semibold">Click to upload</span> or drag
                and drop
              </p>
            </div>
          )}
          <input
            id="dropzone-file"
            type="file"
            name="file"
            className="hidden"
            {...getInputProps()}
          />
        </label>
      </div>
      <div className="flex w-full space-x-2">
        <button
          type="reset"
          className="bg-ctp-red text-ctp-base w-full rounded-lg py-4 hover:bg-red-200 mt-2"
          onClick={handleCancelClick}
        >
          Cancel
        </button>
        <button
          type="button"
          className="bg-ctp-green text-ctp-base w-full rounded-lg py-4 hover:bg-lime-200 mt-2"
          onClick={onConfirmClick}
        >
          Upload
        </button>
      </div>
    </div>
  );
};

export default FileDropper;
