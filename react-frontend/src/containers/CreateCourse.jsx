import React, { useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import { useForm, FormProvider } from "react-hook-form";
import { PlusCircleIcon, ChevronRightIcon } from "@heroicons/react/24/outline";
import FileDropper from "../components/FileDropper";
import Modal from "../components/Modal";
import { Disclosure } from "@headlessui/react";
import { insertCourse } from "../redux/slice/courseSlice";
import { uploadFile } from "../redux/slice/sandboxSlice";

const CreateCourse = () => {
  const methods = useForm();
  const dispatch = useDispatch();
  const { register, handleSubmit, setValue } = methods;
  const [questionArray, setQuestionArray] = useState([]);
  const [fileDropperOpen, setFileDropperOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [confirmedFilename, setConfirmedFilename] = useState("");
  const maxInputLength = 50;

  const handleCourseCreate = (data) => {
    const fileData = { file: data.file[0], lesson: true, lessonName: data.name };
    data.questions = questionArray;
    data.private = false;
    data.binary = data.file[0].name;
    dispatch(insertCourse({ course: data }));
    dispatch(uploadFile(fileData));
  };

  const handleAddQuestion = () => {
    setQuestionArray((questionArray) => [
      ...questionArray,
      {
        question: "",
        answer: "",
        hint: "",
      },
    ]);
  };

  const handleQuestionChange = (event, questionNum) => {
    let data = [...questionArray];
    data[questionNum][event.target.name] = event.target.value;
    setQuestionArray(data);
  };

  const handleFileConfirmClick = () => {
    setFileDropperOpen(false);
    setConfirmedFilename(selectedFile.name);
  };

  const handleFileCancelClick = () => {
    setSelectedFile(null);
    setValue("file", null);
    setConfirmedFilename("");
    setFileDropperOpen(false);
  };

  return (
    <div className="container">
      <FormProvider {...methods}>
        <form
          action=""
          className="w-full"
          onSubmit={handleSubmit(handleCourseCreate)}
        >
          <Modal
            title="Upload binary"
            isOpen={fileDropperOpen}
            closeModal={() => setFileDropperOpen(false)}
          >
            <FileDropper
              setSelectedFile={setSelectedFile}
              selectedFile={selectedFile}
              onConfirmClick={handleFileConfirmClick}
              onCancelClick={handleFileCancelClick}
            />
          </Modal>
          <h1 className="text-5xl font-bold">Create a Lesson</h1>
          <div className="my-5 flex w-full flex-col">
            <label htmlFor="name" className="mb-2">
              Course Name
            </label>
            <input
              type="text"
              id="name"
              placeholder="Course name"
              className="input-primary"
              maxLength={maxInputLength}
              required
              {...register("name")}
            />
          </div>
          <div className="my-5 flex w-full flex-col">
            <label htmlFor="courseDescription" className="mb-2">
              Course Description
            </label>
            <textarea
              id="description"
              placeholder="Course description"
              className="input-primary resize-y"
              required
              {...register("description")}
            />
          </div>
          <div className="my-5 mb-2 flex w-full flex-col">
            <label htmlFor="binary" className="mb-2">
              Binary File
            </label>
            <div className="relative w-full">
              <input
                id="binary"
                placeholder="Upload a file"
                className="input-primary w-full"
                onKeyDown={() => {}}
                onChange={() => {}}
                required
                value={confirmedFilename}
              />
              <div
                className="absolute bottom-0 left-0 right-0 top-0 cursor-pointer"
                onClick={() => setFileDropperOpen(true)}
              />
            </div>
          </div>
          <h1 className="mb-2 text-2xl font-bold">Questions</h1>
          {questionArray.map((item, index) => {
            return (
              <div key={index} className="my-4">
                <Disclosure defaultOpen>
                  {({ open }) => (
                    <>
                      <Disclosure.Button className="flex w-full justify-between rounded-md bg-ctp-mantle px-4 py-2 text-left text-lg font-medium hover:bg-ctp-overlay0 focus:outline-none focus-visible:ring focus-visible:ring-ctp-mauve">
                        <span>{`Question ${index + 1}`}</span>
                        <ChevronRightIcon
                          className={`${
                            open ? "rotate-90 transform" : ""
                          } text-ctp-muave h-5 w-5`}
                        />
                      </Disclosure.Button>
                      <Disclosure.Panel className="text-md overflow-auto px-4 pb-2 pt-2">
                        <div className="my-2 flex w-full flex-col">
                          <label className="my-2">Question {index + 1}</label>
                          <textarea
                            name="question"
                            placeholder="Question text"
                            className="input-primary resize-y"
                            required
                            onChange={(event) =>
                              handleQuestionChange(event, index)
                            }
                            value={item.question}
                          />
                          <label className="my-2">Answer</label>
                          <textarea
                            name="answer"
                            placeholder="Answer"
                            className="input-primary resize-y"
                            required
                            onChange={(event) =>
                              handleQuestionChange(event, index)
                            }
                            value={item.answer}
                          />
                          <label className="my-2">Hint</label>
                          <textarea
                            name="hint"
                            placeholder="Hint"
                            className="input-primary resize-y"
                            onChange={(event) =>
                              handleQuestionChange(event, index)
                            }
                            value={item.hint}
                          />
                        </div>
                      </Disclosure.Panel>
                    </>
                  )}
                </Disclosure>
              </div>
            );
          })}
          <button
            type="button"
            className="btn-primary mt-2 inline-flex w-full items-center justify-center rounded-full"
            onClick={handleAddQuestion}
          >
            <PlusCircleIcon className="mr-2 h-8 w-8" />
            <span>Add Question</span>
          </button>
          <div id="button" className="my-5 flex w-full flex-col">
            <button type="submit" className="btn-confirm">
              <div className="font-bold">Submit</div>
            </button>
          </div>
        </form>
      </FormProvider>
    </div>
  );
};

export default CreateCourse;
