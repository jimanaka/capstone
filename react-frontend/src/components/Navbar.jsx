import { React, Fragment } from "react";
import { Link } from "react-router-dom";
import { Disclosure } from "@headlessui/react";

export default function Example() {
  return (
    <Disclosure as="nav" className="bg-ctp-crust">
      <>
        <div className="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
          <div className="relative flex h-16 items-center justify-between">
            <div className="flex flex-1 items-center justify-center sm:items-stretch sm:justify-start">
              <div className="flex shrink-0 items-center">
                <img
                  className="h-8 w-auto"
                  src="https://tailwindui.com/img/logos/mark.svg?color=indigo&shade=500"
                  alt="Your Company"
                />
              </div>
            </div>
            <div className="absolute inset-y-0 right-0 flex items-center pr-2 sm:static sm:inset-auto sm:ml-6 sm:pr-0"></div>
            <Link to={"/login"}>
              <button className="bg-ctp-surface1 text-ctp-text hover:bg-ctp-mauve hover:text-ctp-surface1 rounded px-4 py-2 font-bold">
                Login
              </button>
            </Link>
          </div>
        </div>
      </>
    </Disclosure>
  );
}
