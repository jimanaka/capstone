import React, { Fragment } from "react";
import { useSelector } from "react-redux";
import { useForm } from "react-hook-form";
import { Dialog, Transition } from "@headlessui/react";
import {
  XMarkIcon,
  ArrowRightCircleIcon,
  LightBulbIcon,
} from "@heroicons/react/24/outline";

const CourseDrawer = ({ isOpen, setIsOpen }) => {
  const currentCourse = useSelector((state) => state.course.currentCourse);
  const { register, handleSubmit } = useForm();

  const handleAnswerSubmit = (data) => {
    console.log(data);
  };

  return (
    <Transition show={isOpen} as={Fragment}>
      <Dialog
        unmount={false}
        onClose={() => setIsOpen(false)}
        className="text-ctp-text fixed inset-0 z-30 overflow-y-auto"
      >
        <div className="flex h-screen w-3/4">
          <Transition.Child
            as={Fragment}
            enter="transition-opacity duration-200 ease-in"
            leave="transition-opacity duration-200 ease-out"
            leaveTo="opacity-0"
          >
            <Dialog.Overlay className="fixed inset-0 z-40" />
          </Transition.Child>

          <Transition.Child
            as={Fragment}
            enter="transform transition duration-200 ease-in-out"
            enterFrom="-translate-x-full"
            enterTo="translate-x-0"
            leave="transform transition duration-200 ease-in-out"
            leaveFrom="translate-x-0"
            leaveTo="-translate-x-full"
          >
            <div className="bg-ctp-mantle z-50 flex w-full max-w-sm flex-col overflow-hidden rounded-r-2xl p-4 text-left align-middle shadow-xl">
              <div>
                <Dialog.Title className="mb-2 flex justify-between pl-2 text-3xl font-bold">
                  Course Questions
                  <button
                    onClick={() => setIsOpen(!isOpen)}
                    className="hover:bg-ctp-surface1 hover:text-ctp-mauve rounded"
                  >
                    <XMarkIcon className="h-6 w-6 text-base" />
                  </button>
                </Dialog.Title>
              </div>
              {currentCourse
                ? currentCourse.questions.map((item, index) => {
                    return (
                      <form
                        action=""
                        className="mt-2 w-full"
                        onSubmit={handleSubmit((data) =>
                          handleAnswerSubmit({ [index + 1]: data[index] }),
                        )}
                        key={index}
                      >
                        <hr className="border-ctp-surface0 mx-1" />
                        <div className="my-2 flex w-full flex-col pl-2">
                          <label
                            htmlFor="username"
                            className="mb-2 flex items-center justify-between"
                          >
                            <p className="mr-3">{item.question}</p>
                            <button className="hover:text-ctp-yellow rounded font-bold">
                              <LightBulbIcon className="hover:text-ctp-yellow h-5 w-5 pr-1" />
                            </button>
                          </label>
                          <div className="flex w-full space-x-2">
                            <input
                              type="text"
                              id="test-input"
                              placeholder="Please input something..."
                              className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 w-full appearance-none rounded-lg border-2 px-1 py-1 text-sm placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2"
                              {...register(`${index}`)}
                            />
                            <button className="hover:text-ctp-mauve rounded">
                              <ArrowRightCircleIcon className="h-6 w-6" />
                            </button>
                          </div>
                        </div>
                      </form>
                    );
                  })
                : null}
            </div>
          </Transition.Child>
        </div>
      </Dialog>
    </Transition>
  );
};

export default CourseDrawer;
