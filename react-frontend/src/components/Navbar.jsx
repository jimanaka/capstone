import React from "react";
import { useEffect, Fragment } from "react";
import { Link } from "react-router-dom";
import { Disclosure, Menu, Transition } from "@headlessui/react";
import { UserCircleIcon } from "@heroicons/react/24/outline";

import { useDispatch, useSelector } from "react-redux";

import { verifyUser, logoutUser } from "../redux/slice/authSlice";

import CircleSpinner from "./CircleSpinner";

const Navbar = () => {
  const user = useSelector((state) => state.auth.user);
  const loading = useSelector((state) => state.auth.loading);
  const dispatch = useDispatch();
  useEffect(() => {
    dispatch(verifyUser());
  }, []);

  const handleLogout = () => {
    console.log("logging out");
    dispatch(logoutUser());
  };

  const loggedInLinks = [
    { link: "/profile", label: "Profile", action: null },
    { link: "/", label: "Logout", action: handleLogout },
  ];
  const loggedOutLinks = [
    { link: "/login", label: "Login", action: null },
    { link: "/register", label: "Register", action: null },
  ];

  let accountMenu = null;
  var links = null;

  if (loading === "pending") {
    accountMenu = (
      <div className="inline-lock relative text-left">
        <CircleSpinner className="icon-outlined mr-2 h-2 w-8" />
      </div>
    );
  } else {
    console.log(user);
    links = user ? loggedInLinks : loggedOutLinks;
    accountMenu = (
      <Menu as="div" className="icon-outlined">
        <div>
          <Menu.Button>
            <UserCircleIcon className="text-ctp-text hover:text-ctp-mauve mr-2 h-8 w-8" />
          </Menu.Button>
        </div>
        <Transition
          as={Fragment}
          enter="transition ease-out duration-100"
          enterFrom="transform opacity-0 scale-95"
          enterTo="transform opacity-100 scale-100"
          leave="transition ease-in duration-75"
          leaveFrom="transform opacity-100 scale-100"
          leaveTo="transform opacity-0 scale-95"
        >
          <Menu.Items className="divide-ctp-surface1 bg-ctp-surface0 absolute right-0 mt-2 w-56 origin-top-right divide-y rounded-md shadow-lg ring-1 ring-black/5 focus:outline-none">
            {links.map((link) => (
              <div className="p-1" key={link.link}>
                <Menu.Item
                  onClick={link.action}
                  className="text-ctp-text hover:bg-ctp-mauve hover:text-ctp-base group flex w-full items-center rounded-md p-2 text-sm font-bold"
                >
                  <Link to={link.link}>
                    <button>{link.label}</button>
                  </Link>
                </Menu.Item>
              </div>
            ))}
          </Menu.Items>
        </Transition>
      </Menu>
    );
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
            {accountMenu}
          </div>
        </div>
      </>
    </Disclosure>
  );
};

export default Navbar;
