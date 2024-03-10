import React from "react";

const SearchBox = () => {
  return (
    <div className="box">
      <div className="box-wrapper">
        <div className="input-primary flex items-center rounded shadow-sm">
          <button className="outline-none focus:outline-none">
            <svg
              className="h-5 w-5 cursor-pointer"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
            </svg>
          </button>
          <input
            type="search"
            name=""
            id=""
            placeholder="search for courses"
            x-model="q"
            className="text-md w-full bg-transparent pl-4 outline-none focus:outline-none"
          />
          <div className="select">
            <select
              name=""
              id=""
              x-model="image_type"
              className="bg-transparent text-sm outline-none focus:outline-none"
              defaultValue={"all"}
            >
              <option value="photo">Name</option>
              <option value="illustration">Author</option>
              <option value="vector">Tags</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SearchBox;
