import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { PlusCircleIcon } from "@heroicons/react/24/outline";

const CreateCourse = () => {
  const { register, handleSubmit } = useForm();
  const [questionArray, setQuestionArray] = useState([]);
  const maxInputLength = 25;

  const handleCourseCreate = (data) => {
    console.log(data);
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

  const Question = () => {
    return <div>ls</div>;
  };

  return (
    <div className="container">
      <h1 className="text-5xl font-bold">Create a Lesson</h1>
      <form
        action=""
        className="w-full"
        onSubmit={handleSubmit(handleCourseCreate)}
      >
        <div className="my-5 flex w-full flex-col">
          <label htmlFor="courseName" className="mb-2">
            Course Name
          </label>
          <input
            type="text"
            id="courseName"
            placeholder="Course name"
            className="input-primary"
            maxLength={maxInputLength}
            required
            {...register("courseName")}
          />
        </div>
        <div className="my-5 flex w-full flex-col">
          <label htmlFor="courseDescription" className="mb-2">
            Course Description
          </label>
          <textarea
            id="courseDescription"
            placeholder="Course description"
            className="input-primary resize-y"
            maxLength={maxInputLength}
            required
            {...register("courseDescription")}
          />
        </div>
        {questionArray.map((item, index) => {
          return <Question key={index} />;
        })}
        <button
          type="button"
          className="btn-primary mt-2 inline-flex items-center rounded-full w-full justify-center"
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
    </div>
  );
};

export default CreateCourse;
