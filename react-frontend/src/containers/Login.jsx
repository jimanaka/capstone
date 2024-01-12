import React from "react";
import { useForm } from "react-hook-form";
import { useDispatch, useSelector } from "react-redux";
import { loginUser } from "../redux/slice/authSlice";

const Login = () => {
  const { register, handleSubmit } = useForm();

  const dispatch = useDispatch();
  const user = useSelector((state) => state.auth.user);
  const authError = useSelector((state) => state.auth.error);
  const authloading = useSelector((state) => state.auth.loading);

  const handleLogin = (data) => {
    dispatch(loginUser(data));
  };

  return (
    <body>
      <div className="container mx-auto px-6">
        <div className="flex h-[calc(100vh-96px)] flex-col justify-evenly text-center md:flex-row md:items-center md:text-left">
          <div className="flex w-full flex-col">
            <div>
              <svg
                className="fill-stroke mx-auto h-20 w-20 md:float-left"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"
                ></path>
              </svg>
            </div>
            <h1 className="text-5xl font-bold">Client Area</h1>
            <p className="mx-auto w-5/12 md:mx-0">
              Control and monitorize your website data from dashboard.
            </p>
          </div>
          <div className="mx-auto w-full md:mx-0 md:w-full lg:w-9/12">
            <div className="flex w-full flex-col rounded-xl p-10">
              <h2 className="mb-5 text-left text-2xl font-bold">Signin</h2>
              <form
                action=""
                className="w-full"
                onSubmit={handleSubmit(handleLogin)}
              >
                <div id="input" className="my-5 flex w-full flex-col">
                  <label htmlFor="username" className="mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    id="username"
                    placeholder="Please insert your username"
                    className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 appearance-none rounded-lg border-2 px-4 py-3 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2"
                    {...register("username")}
                  />
                </div>
                <div id="input" className="my-5 flex w-full flex-col">
                  <label htmlFor="password" className="mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    id="password"
                    placeholder="Please insert your password"
                    className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 appearance-none rounded-lg border-2 px-4 py-3 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2"
                    {...register("password")}
                  />
                </div>
                <div id="button" className="my-5 flex w-full flex-col">
                  <button
                    type="submit"
                    className="bg-ctp-green text-ctp-base w-full rounded-lg py-4 hover:bg-lime-200"
                  >
                    <div className="flex flex-row items-center justify-center">
                      <div className="mr-2">
                        <svg
                          className="h-6 w-6"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                          xmlns="http://www.w3.org/2000/svg"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="2"
                            d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"
                          ></path>
                        </svg>
                      </div>
                      <div className="font-bold">Signin</div>
                    </div>
                  </button>
                  <div className="mt-5 flex justify-evenly">
                    <a
                      href="#"
                      className="hover:text-ctp-text w-full text-center font-medium text-gray-500"
                    >
                      Recover password!
                    </a>
                    <a
                      href="#"
                      className="hover:text-ctp-text w-full text-center font-medium text-gray-500"
                    >
                      Signup!
                    </a>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </body>
  );
};

export default Login;
