import { createSlice } from "@reduxjs/toolkit";

const createCourseSlice = createSlice({
  name: "createCourse",
  initialState: {
    title: null,
    description: null,
    questions: [],
    error: null,
    loading: "idle", // idle | pending | succeeded | failed
  },
  reducers: {
    setTitle: (state, action) => {
      state.title = action.payload;
    },
    setDescription: (state, action) => {
      state.description = action.payload;
    },
    setQuestions: (state, action) => {
      state.questions = action.payload;
    },
    addQuestion: (state, action) => {
      state.questions.push(action.payload);
    },
  },
});

export const { setTitle, setDescription, setQuestions, addQuestion } =
  createCourseSlice.actions;
export default createCourseSlice.reducer;
