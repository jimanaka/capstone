import React, { Fragment, useEffect, useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useForm } from "react-hook-form";
import { Dialog, Transition } from "@headlessui/react";
import {
  XMarkIcon,
  ArrowRightCircleIcon,
  LightBulbIcon,
  CheckCircleIcon,
} from "@heroicons/react/24/outline";
import { submitAnswer, getCompleteQuestions } from "../redux/slice/courseSlice";

const CourseDrawer = ({ isOpen, setIsOpen }) => {
  const dispatch = useDispatch();
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
    setValue,
  } = useForm();
  const currentCourse = useSelector((state) => state.course.currentCourse);
  const completeQuestions = useSelector(
    (state) => state.course.completeQuestions,
  );
  const [showHint, setShowHint] = useState([]);

  const handleAnswerSubmit = (data) => {
    dispatch(submitAnswer(data)).then((res) => {
      if (res.error) {
        setError(`${data.questionNum - 1}`, {
          type: "manual",
          message: "Incorrect Answer",
        });
      } else {
        dispatch(
          getCompleteQuestions({ courseId: currentCourse._id.$oid }),
        ).then((res2) => {
          if (res2.error) {
            return;
          }
          setValue(`${data.questionNum - 1}`, "");
        });
      }
    });
  };

  const handleShowHintPress = (index) => {
    let newHintArray = [...showHint];
    newHintArray[index] = !newHintArray[index];
    setShowHint(newHintArray);
  };

  useEffect(() => {
    if (currentCourse) {
      dispatch(getCompleteQuestions({ courseId: currentCourse._id.$oid }));
      setShowHint(new Array(currentCourse.questions.length).fill(false));
    }
  }, [currentCourse]);

  return (
    <Transition show={isOpen} as={Fragment}>
      <Dialog
        unmount={false}
        onClose={() => setIsOpen(false)}
        className="fixed inset-0 z-30 overflow-y-auto text-ctp-text"
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
            <div className="z-50 flex w-full max-w-sm flex-col overflow-hidden rounded-r-2xl bg-ctp-mantle p-4 text-left align-middle shadow-xl">
              <div>
                <Dialog.Title className="mb-2 flex justify-between pl-2 text-3xl font-bold">
                  Course Questions
                  <button
                    onClick={() => setIsOpen(!isOpen)}
                    className="rounded hover:bg-ctp-surface1 hover:text-ctp-mauve"
                  >
                    <XMarkIcon className="h-6 w-6 text-base" />
                  </button>
                </Dialog.Title>
              </div>
              {currentCourse
                ? currentCourse.questions.map((item, index) => {
                    let isComplete = completeQuestions.includes(index + 1);
                    return (
                      <form
                        action=""
                        className="mt-2 w-full"
                        onSubmit={handleSubmit((data) =>
                          handleAnswerSubmit({
                            questionNum: index + 1,
                            submittedAnswer: data[index],
                          }),
                        )}
                        key={index}
                      >
                        <hr className="mx-1 border-ctp-surface0" />
                        <div className="my-2 flex w-full flex-col pl-2">
                          <label
                            htmlFor="username"
                            className={`mb-2 flex items-center justify-between ${
                              isComplete ? "text-ctp-green" : null
                            }`}
                          >
                            <p className="mr-3">{item.question}</p>
                            <button
                              type="button"
                              onClick={() => handleShowHintPress(index)}
                              className="rounded font-bold text-ctp-text hover:text-ctp-yellow"
                            >
                              <LightBulbIcon
                                className={`h-5 w-5 pr-1 hover:text-ctp-yellow ${
                                  showHint[index] ? "text-ctp-yellow" : null
                                }`}
                              />
                            </button>
                          </label>
                          <div className="flex w-full space-x-2">
                            <input
                              type="text"
                              id="test-input"
                              placeholder={
                                isComplete
                                  ? currentCourse.questions[index].answer
                                  : "Input answer here..."
                              }
                              disabled={isComplete ? true : false}
                              className={`bg-ctp-surface0 ${
                                errors[index]
                                  ? "border-ctp-red focus:ring-ctp-red"
                                  : isComplete
                                    ? "border-ctp-green focus:ring-ctp-green"
                                    : "border-ctp-surface1 focus:ring-ctp-mauve"
                              } w-full appearance-none rounded-lg border-2 px-1 py-1 text-sm placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2`}
                              {...register(`${index}`)}
                            />
                            <button
                              className="rounded hover:text-ctp-green"
                              disabled={isComplete ? true : false}
                            >
                              {isComplete ? (
                                <CheckCircleIcon className="h-6 w-6 text-ctp-green" />
                              ) : (
                                <ArrowRightCircleIcon className="h-6 w-6" />
                              )}
                            </button>
                          </div>
                          {errors[`${index}`] && (
                            <p className="text-xs text-ctp-red">
                              {errors[`${index}`].message}
                            </p>
                          )}
                          {showHint[index] ? (
                            currentCourse.questions[index].hint &&
                            currentCourse.questions[index].hint !== "" ? (
                              <p className="mt-1">
                                Hint: {currentCourse.questions[index].hint}
                              </p>
                            ) : (
                              <p className="mt-1">No hint available</p>
                            )
                          ) : null}
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
