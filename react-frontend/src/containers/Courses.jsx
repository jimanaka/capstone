import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import { listAvailableCourses } from "../redux/slice/courseSlice";
import { PlusCircleIcon } from "@heroicons/react/24/outline";
import CodeView from "../components/CodeView";
import SearchBox from "../components/SearchBox";

const Courses = () => {
  const dispatch = useDispatch();
  const courses = useSelector((state) => state.course.courses);

  const [selectedCourse, setSelectedCourse] = useState(null);

  useEffect(() => {
    dispatch(listAvailableCourses());
  }, []);

  useEffect(() => {
    console.log(selectedCourse);
  }, [selectedCourse]);

  const handleCourseListItemClick = (item) => {
    setSelectedCourse(item);
  }

  const CourseListItem = ({ title, author }) => {
    return (
      <>
        <div className="h-[4.5rem] w-full rounded bg-ctp-mantle px-4 py-2 shadow-sm">
          <div className="flex w-full justify-between">
            <h2 className="text-lg">{title}</h2>
            <h3 className="text-md text-ctp-subtext0">Author: {author}</h3>
          </div>
        <h3 className="text-sm text-ctp-subtext0">Tags here...</h3>
        </div>
      </>
    );
  };

  return (
    <div className="flex flex-1 flex-col px-11 py-4 ">
      <div className="flex w-full items-center justify-between">
        <h1 className="text-6xl font-extrabold">Courses</h1>
        <Link to={"/create-course"}>
          <button className="btn-primary mt-4 inline-flex items-center rounded-full">
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Create Course</span>
          </button>
        </Link>
      </div>
      <div className="mt-4 flex flex-1 space-x-4">
        <div className="flex flex-1 flex-col overflow-hidden">
          <SearchBox />
          <div className="overflow-scroll">
            <ul className="mt-4">
              {courses.length > 0
                ? courses.map((item, index) => {
                    return (
                      <li key={index} onClick={() => handleCourseListItemClick(item)}>
                        <CourseListItem title={item.name} author={item.author}/>
                      </li>
                    );
                  })
                : null}
            </ul>
          </div>
        </div>
        <CodeView className="flex flex-1" />
      </div>
    </div>
  );
};

export default Courses;
