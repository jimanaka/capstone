import React from "react";
import { Link } from "react-router-dom";

const Home = () => {
  return (
    <>
      <div className="relative top-44 flex h-[30rem] items-center justify-center space-x-32">
        {/* left card */}
        <div className="bg-ctp-crust h-full w-[30rem] p-8 shadow-lg">
          <h1 className="from-ctp-pink to-ctp-mauve flex justify-center bg-gradient-to-r bg-clip-text text-5xl font-bold text-transparent">
            Courses
          </h1>
          <div className="h-[18rem]">
            <p className="flex w-auto justify-center p-8">
              Some text description of the available courses
            </p>
          </div>
          <hr className="bg-ctp-surface1" />
          <Link to={"/courses"} className="flex justify-center">
            <button className="btn-primary mt-7 w-full">Go to Courses!</button>
          </Link>
        </div>
        {/* right card */}
        <div className="bg-ctp-crust h-full w-[30rem] p-8 shadow-lg">
          <h1 className="from-ctp-pink to-ctp-mauve flex justify-center bg-gradient-to-r bg-clip-text text-5xl font-bold text-transparent">
            Sandbox
          </h1>
          <div className="h-[18rem]">
            <p className="flex w-auto justify-center p-8">
              Some text description of the sandbox
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
