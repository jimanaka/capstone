import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import {
  getAvailableCourses,
  getRegisteredCourses,
  registerCourse,
} from "../redux/slice/courseSlice";
import { PlusCircleIcon } from "@heroicons/react/24/outline";
import CodeView from "../components/CodeView";
import SearchBox from "../components/SearchBox";

const Courses = () => {
  const dispatch = useDispatch();
  const courses = useSelector((state) => state.course.courses);
  const registeredCourses = useSelector(
    (state) => state.course.registeredCourses,
  );

  const [selectedCourse, setSelectedCourse] = useState(null);

  useEffect(() => {
    dispatch(getAvailableCourses());
    dispatch(getRegisteredCourses());
  }, []);

  const handleCourseListItemClick = (item) => {
    setSelectedCourse(item);
  };

  const handleRegisterCourseClick = () => {
    dispatch(registerCourse({ courseId: selectedCourse._id.$oid })).then((res) => {
      if (res.meta.requestStatus === "fulfilled") {
        dispatch(getRegisteredCourses());
      }
    })
  };

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
    <div className="flex flex-1 flex-col px-11 py-4">
      <div className="flex w-full items-center justify-between">
        <h1 className="text-6xl font-extrabold">Courses</h1>
        <Link to={"/create-course"}>
          <button className="btn-primary mt-4 inline-flex items-center rounded-full">
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Create Course</span>
          </button>
        </Link>
      </div>
      <div className="mt-4 flex max-h-[calc(100vh_-_11rem)] flex-1 space-x-4">
        <div className="flex flex-1 flex-col">
          <SearchBox />
          <div className="mt-4 flex-1 overflow-scroll">
            <ul>
              {courses.length > 0
                ? courses.map((item, index) => {
                    let registered = registeredCourses.includes(item._id.$oid);
                    return (
                      <li
                        key={index}
                        className={`border ${
                          registered
                            ? "border-ctp-green"
                            : "border-ctp-surface0"
                        }`}
                        onClick={() => handleCourseListItemClick(item)}
                      >
                        <CourseListItem
                          title={item.name}
                          author={item.author}
                          registered={registered}
                        />
                      </li>
                    );
                  })
                : null}
            </ul>
          </div>
        </div>
        <CodeView className="flex flex-1 flex-col p-8 text-left">
          {selectedCourse ? (
            <>
              <h2 className="text-4xl">{selectedCourse.name}</h2>
              <hr className="mt-4 border-ctp-surface1" />
              <h3 className="mt-4 text-2xl">Description</h3>
              <code className="mt-4 flex flex-1 overflow-scroll bg-ctp-mantle p-2">
                {selectedCourse.description}
              </code>
              <h3 className="text-1xl mt-4">Tags here...</h3>
              <div className="flex justify-between">
                <h3 className="mt-4 text-2xl">
                  Author: {selectedCourse.author}
                </h3>
                <button
                  className="btn-primary"
                  onClick={handleRegisterCourseClick}
                >
                  Register
                </button>
              </div>
            </>
          ) : null}
        </CodeView>
      </div>
    </div>
  );
};

export default Courses;
