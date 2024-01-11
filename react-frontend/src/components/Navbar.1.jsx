import React from "react";
import { useEffect, Fragment } from "react";
import { Link } from "react-router-dom";
import { Disclosure, Menu, Transition } from "@headlessui/react";
import { UserCircleIcon } from "@heroicons/react/24/outline";
import { useDispatch, useSelector } from "react-redux";
import { verifyUser } from "../redux/slice/authSlice";
import CircleSpinner from "./CircleSpinner";

export const Navbar = () => {
  const user = useSelector((state) => state.auth.user);
  const loading = useSelector((state) => state.auth.loading);
  const dispatch = useDispatch();
  useEffect(() => {
    dispatch(verifyUser());
  }, []);

  const loggedInLinks = [
    { link: "/profile", label: "Profile" },
    { link: "/logout", label: "Logout" },
  ];

  let button = null;

  if (loading === "pending") {
    button = (
      <div>
        <CircleSpinner className="icon-outlined" />;
      </div>);
  } else {
    if (user) {
      button = (
        <Menu as="div" className="inline-lock relative z-50 text-left">
          <div>
            <Menu.Button>
              <UserCircleIcon className="icon-outlined" />
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
            <Menu.Items className="absolute right-0 mt-2 w-56 origin-top-right divide-y divide-gray-100 rounded-md bg-white shadow-lg ring-1 ring-black/5 focus:outline-none">
              {loggedInLinks.map((link) => (
                <div className="p-1" key={link.link}>
                  <Menu.Item className="group flex w-full items-center rounded-md p-2 text-sm text-gray-900 active:bg-violet-500 active:text-white">
                    <Link to={link.link}>
                      <button>{link.label}</button>
                    </Link>
                  </Menu.Item>
                </div>
              ))}
              {/* <div className="p-1 ">
                      <Menu.Item>
                        {({ active }) => (
                          <button
                            className={`${
                              active ? "bg-violet-500 text-white" : "text-gray-900"
                            } group flex w-full items-center rounded-md p-2 text-sm`}
                          >
                            Edit
                          </button>
                        )}
                      </Menu.Item> */}
            </Menu.Items>
          </Transition>
        </Menu>
      );
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
                    alt="Your Company" />
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
