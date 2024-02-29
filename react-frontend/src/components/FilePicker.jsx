import React from "react";
import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { listFiles } from "../redux/slice/sandboxSlice";

const FilePicker = () => {
  const dispatch = useDispatch();
  const fileList = useSelector((state) => state.sandbox.fileList);

  useEffect(() => {
    dispatch(listFiles());
  }, []);

  return (
    <div>
      <ul>
        {fileList.length > 0
          ? fileList.map((file, index) => {
              return (
                <li key={index}>
                  <p>{file}</p>
                </li>
              );
            })
          : null}
      </ul>
    </div>
  );
};

export default FilePicker;
