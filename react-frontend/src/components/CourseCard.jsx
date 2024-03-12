import React from "react";

const CourseCard = ({ title, description, tags }) => {
  return (
    <div className="flex flex-col bg-ctp-mantle max-w-sm overflow-hidden rounded shadow-lg h-[24rem]">
      <img
        className="max-w-full object-scale-down"
        src="/images/test.jpg"
        alt="Sunset in the mountains"
      />
      <div className="flex flex-col px-6 py-4 grow overflow-hidden">
        <div className="mb-2 text-xl font-bold overflow-ellipsis overflow-hidden shrink-0">{title}</div>
        <div className="text-base overflow-y-scroll max-h-min">{description}</div>
      </div>
      <div className="px-6 pb-2 pt-2">
        <span className="mb-2 mr-2 inline-block rounded-full bg-gray-200 px-3 py-1 text-sm font-semibold text-gray-700">
          C/C++
        </span>
        <span className="mb-2 mr-2 inline-block rounded-full bg-gray-200 px-3 py-1 text-sm font-semibold text-gray-700">
          Easy
        </span>
        <span className="mb-2 mr-2 inline-block rounded-full bg-gray-200 px-3 py-1 text-sm font-semibold text-gray-700">
          Other Tag
        </span>
      </div>
    </div>
  );
};

export default CourseCard;
