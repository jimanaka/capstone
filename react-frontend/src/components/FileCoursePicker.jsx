import React from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { PlusCircleIcon, TrashIcon } from "@heroicons/react/24/outline";
import { useDispatch, useSelector } from "react-redux";
import {
  listFiles,
  deleteFile,
  setCurrentFilePath,
} from "../redux/slice/sandboxSlice";
import { getRegisteredCourses } from "../redux/slice/courseSlice";

const FileCoursePicker = ({ handleFileAddPress, setVisible }) => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const fileList = useSelector((state) => state.sandbox.fileList);
  const registeredCourseList = useSelector(
    (state) => state.course.registeredCourses,
  );
  const user = useSelector((state) => state.auth.user);
  const [isDisplayCourse, setIsDisplayCourse] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [highlightLine, setHighlightLine] = useState(null);
  let displayList = isDisplayCourse ? registeredCourseList : fileList;

  useEffect(() => {
    dispatch(getRegisteredCourses());
    dispatch(listFiles());

    return () => {
      setSelectedFile(null);
    };
  }, []);

  useEffect(() => {
    console.log(selectedFile);
  }, []);

  const handleListPress = (item, index) => {
    setSelectedFile(item);
    setHighlightLine(index);
  };

  const handleDeletePress = (filename) => {
    dispatch(deleteFile({ filename: filename }));
  };

  //todo make this a const
  const handleConfirmClick = () => {
    if (selectedFile) {
      if (isDisplayCourse) {
        dispatch(
          setCurrentFilePath(
            "/app/lesson-uploads/" +
              selectedFile.name +
              "/" +
              selectedFile.binary,
          ),
        );
      } else {
        dispatch(
          setCurrentFilePath("/app/user-uploads/" + user + "/" + selectedFile),
        );
      }
      setVisible ? setVisible(false) : null;
    }
  };

  const handleDisplayChange = () => {
    setIsDisplayCourse(!isDisplayCourse);
    setSelectedFile(null);
    setHighlightLine(null);
  };

  return (
    <>
      <ul>
        <hr className="border-ctp-surface1 mx-1" />
        {displayList && displayList.length > 0
          ? displayList.map((item, index) => {
              let highlight = index === highlightLine ? true : false;
              let itemName = isDisplayCourse ? item.name : item;
              return (
                <div key={index}>
                  <div
                    className={`${
                      highlight ? "bg-ctp-overlay0" : null
                    } flex justify-between items-center rounded-md`}
                    onClick={() => handleListPress(item, index)}
                  >
                    <li className="mt-2 mb-2 pl-4">{itemName}</li>
                    {isDisplayCourse ? null : (
                      <TrashIcon
                        className="h-8 w-8 text-ctp-red hover:text-red-300 hover:bg-ctp-mantle active:bg-ctp-crust rounded-md p-1"
                        onClick={() => handleDeletePress(itemName)}
                      />
                    )}
                  </div>
                  <hr className="border-ctp-surface1 mx-1" />
                </div>
              );
            })
          : null}
      </ul>
      <div className="flex justify-between">
        {isDisplayCourse ? (
          <button
            className="btn-primary mt-4 inline-flex items-center rounded-lg"
            onClick={() => navigate("/courses")}
          >
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Add Course</span>
          </button>
        ) : (
          <button
            className="btn-primary mt-4 inline-flex items-center rounded-lg"
            onClick={handleFileAddPress}
          >
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Add File</span>
          </button>
        )}
        <button
          type="button"
          className="btn-primary mt-4 items-center rounded-lg"
          onClick={handleDisplayChange}
        >
          {isDisplayCourse ? "Show Files" : "Show Courses"}
        </button>
        <button
          className="btn-confirm h-10 w-28 mt-4"
          onClick={handleConfirmClick}
        >
          Confirm
        </button>
      </div>
    </>
  );
};

export default FileCoursePicker;
