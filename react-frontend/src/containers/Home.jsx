import React from "react";
import { Link } from "react-router-dom";

const Home = () => {
  return (
    <>
      <div className="relative top-44 flex h-[30rem] items-center justify-center px-56">
        {/* left card */}
        <div className="h-full w-[30rem] bg-ctp-crust p-8 shadow-lg">
          <h1 className="flex justify-center bg-gradient-to-r from-ctp-pink to-ctp-mauve bg-clip-text text-5xl font-bold text-transparent">
            Courses
          </h1>
          <div className="h-[18rem] justify-center text-center">
            <p className="flex w-auto p-8">
              Browse, search, register, and create reverse engineering lessons.
            </p>
          </div>
          <hr className="bg-ctp-surface1" />
          <Link to={"/courses"} className="flex justify-center">
            <button className="btn-primary mt-7 w-full">Go to Courses!</button>
          </Link>
        </div>
        {/* right card */}
        <div className="ml-32 h-full w-[30rem] bg-ctp-crust p-8 shadow-lg">
          <h1 className="flex justify-center bg-gradient-to-r from-ctp-pink to-ctp-mauve bg-clip-text text-5xl font-bold text-transparent">
            Sandbox
          </h1>
          <div className="h-[18rem] justify-center text-center">
            <p className="w-auto p-8">
              Freely explore and exploit 32/64-bit binaries using various
              reverse engineering tools.
            </p>
            <p className="w-auto px-8">
              Upload your own executable files or use pre-loaded files from your
              registered courses.
            </p>
          </div>
          <hr className="bg-ctp-surface1" />
          <Link to={"/sandbox"} className="flex justify-center">
            <button className="btn-primary mt-7 w-full">Go to Sandbox!</button>
          </Link>
        </div>
      </div>
    </>
  );
};

export default Home;
