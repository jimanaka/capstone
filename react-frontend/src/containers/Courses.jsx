import React, { useEffect } from "react";
import { Link } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { listAvailableCourses } from "../redux/slice/courseSlice";
import { PlusCircleIcon } from "@heroicons/react/24/outline";
import CodeView from "../components/CodeView";
import SearchBox from "../components/SearchBox";

const Courses = () => {
  const dispatch = useDispatch();
  const courses = useSelector((state) => state.course.courses);

  useEffect(() => {
    dispatch(listAvailableCourses());
  }, []);

  return (
    <div className="flex flex-col px-11 py-4 flex-1 ">
      <div className="flex w-full items-center justify-between">
        <h1 className="text-6xl font-extrabold">Courses</h1>
        <Link to={"/create-course"}>
          <button className="btn-primary mt-4 inline-flex items-center rounded-full">
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Create Course</span>
          </button>
        </Link>
      </div>
      <div className="flex space-x-4 mt-4 flex-1">
        <div className="flex flex-col flex-1">
          <SearchBox/>
        </div>
        <CodeView className="flex flex-1"/>
      </div>
    </div>
  );
};

export default Courses;
