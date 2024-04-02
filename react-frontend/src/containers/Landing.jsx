import React from "react";
import { useNavigate } from "react-router-dom";

const Landing = () => {
  const navigate = useNavigate();
  return (
    <>
      <div className="container mt-8 text-center">
        <h1 className="text-7xl font-bold">
          Learn & Practice Reverse Engineering
        </h1>
        <h2 className="mt-12 text-xl">
          Utilize a suite of reverse engineering and binary exploitation tools.
          Augment learning by creating, sharing, and completing guided reverse
          engineering courses. No setup or local installations required!
        </h2>
        <div className="mt-16 flex items-center justify-center space-x-12">
          <button
            onClick={() => navigate("/login")}
            className="btn-confirm rounded-full px-8 py-2"
          >
            Login Here
          </button>
          <p>or</p>
          <button
            onClick={() => navigate("/register")}
            className="btn-primary rounded-full px-8 py-2"
          >
            Signup Here
          </button>
        </div>
        <p className="mt-8">Already logged in?</p>
        <button
          onClick={() => navigate("/home")}
          className="btn-primary mt-4 rounded-full px-8 py-2"
        >
          Start Reversing!
        </button>
        <hr className="mt-16 w-full border border-ctp-surface1" />
      </div>
      <div className="px-52 pb-16">
        <div className="mt-8 flex flex-col items-center justify-center">
          <h1 className="text-2xl font-bold">
            Dissasemble and Decompile Files
          </h1>
          <img src="/images/Code-Listing2.png" />
        </div>
        <hr className="mt-16 w-full border border-ctp-surface1" />
        <div className="mt-8 flex flex-col items-center justify-center">
          <h1 className="text-2xl font-bold">Live Debugging</h1>
          <img src="/images/Debugger.png" />
        </div>
        <hr className="mt-16 w-full border border-ctp-surface1" />
        <h1 className="mt-8 text-center text-2xl font-bold">
          Build Payloads & Automated ROP Chains
        </h1>
        <div className="mt-4 flex items-center justify-center">
          <img src="/images/Payload-Builder1.png" />
          <img src="/images/Payload-Builder3.png" />
        </div>
        <hr className="mt-16 w-full border border-ctp-surface1" />
        <div className="mt-8 flex items-center justify-center">
          <h1 className="w-full space-x-12 text-left text-2xl font-bold">
            Automatically Generate Python and Bash Code for Your payload
          </h1>
          <img className="w-full" src="/images/Payload-Builder4.png" />
        </div>
        <hr className="mt-16 w-full border border-ctp-surface1" />
        <div className="mt-8 flex items-center justify-center">
          <img className="w-full" src="/images/Course.png" />
          <h1 className="w-full space-x-12 text-center text-2xl font-bold">
            Follow Guided Lessons while Reverse Engineering
          </h1>
        </div>
      </div>
    </>
  );
};

export default Landing;
