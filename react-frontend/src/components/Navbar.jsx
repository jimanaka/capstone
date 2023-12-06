import { React, Fragment } from "react";
import { Link } from "react-router-dom";
import { Disclosure } from "@headlessui/react";

export default function Example() {
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
            <Link to={"/login"}>
              <button className="btn-primary">Login</button>
            </Link>
          </div>
        </div>
      </>
    </Disclosure>
  );
}
