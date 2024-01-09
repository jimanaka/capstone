import React from "react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Disclosure } from "@headlessui/react";

import { useDispatch, useSelector } from "react-redux";

import { verifyUser } from "../redux/slice/authSlice";

import CircleSpinner from "./CircleSpinner";

const Navbar = () => {
  const user = useSelector((state) => state.auth.user);
  const loading = useSelector((state) => state.auth.loading);
  const dispatch = useDispatch();
  useEffect(() => {
    dispatch(verifyUser());
  }, []);

  let button = null;

  if (loading === "pending") {
    button = (
      <button className="btn-primary w-20">
        <CircleSpinner />
      </button>
    );
  } else {
    if (user) {
      button = <button className="btn-primary">Profile</button>;
    } else {
      button = (
        <Link to={"/login"}>
          <button className="btn-primary">Login</button>
        </Link>
      );
    }
  }

  return (
    <Disclosure as="nav" className="bg-ctp-crust">
      <>
        <div className="mx-auto px-2 sm:px-6 lg:px-8">
          <div className="relative flex h-16 items-center justify-between">
            <div className="flex flex-1 items-center justify-center sm:items-stretch sm:justify-start">
              <Link to={"/"}>
                <div className="flex shrink-0 items-center">
                  <img
                    className="h-8 w-auto"
                    src="https://tailwindui.com/img/logos/mark.svg?color=indigo&shade=500"
                    alt="Your Company"
                  />
                </div>
              </Link>
            </div>
            {button}
          </div>
        </div>
      </>
    </Disclosure>
  );
};

export default Navbar;
