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
import { getRegisteredCourses, loadCourse } from "../redux/slice/courseSlice";

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
        dispatch(loadCourse({ courseId: selectedFile._id.$oid }));
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
        <hr className="mx-1 border-ctp-surface1" />
        {displayList && displayList.length > 0
          ? displayList.map((item, index) => {
              let highlight = index === highlightLine ? true : false;
              let itemName = isDisplayCourse ? item.name : item;
              return (
                <div key={index}>
                  <div
                    className={`${
                      highlight ? "bg-ctp-overlay0" : null
                    } flex items-center justify-between rounded-md`}
                    onClick={() => handleListPress(item, index)}
                  >
                    <li className="mb-2 mt-2 pl-4">{itemName}</li>
                    {isDisplayCourse ? null : (
                      <TrashIcon
                        className="h-8 w-8 rounded-md p-1 text-ctp-red hover:bg-ctp-mantle hover:text-red-300 active:bg-ctp-crust"
                        onClick={() => handleDeletePress(itemName)}
                      />
                    )}
                  </div>
                  <hr className="mx-1 border-ctp-surface1" />
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
          className="btn-confirm mt-4 h-10 w-28"
          onClick={handleConfirmClick}
        >
          Confirm
        </button>
      </div>
    </>
  );
};

export default FileCoursePicker;
