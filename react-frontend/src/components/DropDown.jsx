import React from "react";
import { Disclosure } from "@headlessui/react";
import { ChevronRightIcon } from "@heroicons/react/20/solid";

const DropDown = ({ label, items, type }) => {
  const VariableTypeList = () => {
    switch (type) {
      case "fileInfo":
        return (
          <ul>
            {items
              ? Object.keys(items).map((k) => {
                  return Object.keys(items[k]).map((kk, ii) => {
                    return (
                      <li key={`${k}${ii}`} className="whitespace-nowrap">
                        {kk}: {items[k][kk].toString()}
                      </li>
                    );
                  });
                })
              : null}
          </ul>
        );
      case "strings":
        return (
          <ul>
            {items.length > 0
              ? items.map((item) => {
                  return <li key={`${type}:${item.string}`}>{item.string}</li>;
                })
              : null}
          </ul>
        )
      default:
        return (
          <ul>
            {items.length > 0
              ? items.map((item) => {
                  return <li key={`${type}:${item.name}`}>{item.name}</li>;
                })
              : null}
          </ul>
        );
    }
  };

  return (
    <div>
      <Disclosure>
        {({ open }) => (
          <>
            <Disclosure.Button className="bg-ctp-mantle flex w-full justify-between rounded-md px-4 py-2 text-left text-lg font-medium hover:bg-ctp-overlay0 focus:outline-none focus-visible:ring focus-visible:ring-ctp-mauve">
              <span>{label}</span>
              <ChevronRightIcon
                className={`${
                  open ? "rotate-90 transform" : ""
                } h-5 w-5 text-ctp-muave`}
              />
            </Disclosure.Button>
            <Disclosure.Panel className="px-4 pb-2 pt-2 text-md overflow-auto">
              {VariableTypeList}
            </Disclosure.Panel>
          </>
        )}
      </Disclosure>
    </div>
  );
};

export default DropDown;
