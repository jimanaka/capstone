import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  insertCourseService,
  getAvailableCoursesService,
  registerCourseService,
  getRegisteredCoursesService,
  getRegisteredCourseService,
  addCorrectAnswerService,
  getCompleteQuestionsService,
} from "../service/courseService";

export const submitAnswer = createAsyncThunk(
  "course/submitAnswer",
  async ({ questionNum, submittedAnswer }, { rejectWithValue, getState }) => {
    try {
      const { course } = getState();
      const questionIndex = questionNum - 1;
      if (
        submittedAnswer === course.currentCourse.questions[questionIndex].answer
      ) {
        const response = await addCorrectAnswerService({
          courseId: course.currentCourse._id.$oid,
          questionNum: questionNum,
        });
        return response.data;
      } else {
        return rejectWithValue("Incorrect answer");
      }
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const getCompleteQuestions = createAsyncThunk(
  "course/getCompleteQuestions",
  async ({ courseId }, { rejectWithValue }) => {
    try {
      const response = await getCompleteQuestionsService({ courseId });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const insertCourse = createAsyncThunk(
  "course/insert",
  async ({ course }, { rejectWithValue }) => {
    try {
      const response = await insertCourseService({ course });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const getAvailableCourses = createAsyncThunk(
  "course/getAvailableCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await getAvailableCoursesService();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const getRegisteredCourses = createAsyncThunk(
  "course/getRegisteredCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await getRegisteredCoursesService();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const registerCourse = createAsyncThunk(
  "course/registerCourse",
  async ({ courseId }, { rejectWithValue }) => {
    try {
      const response = await registerCourseService({ courseId });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const loadCourse = createAsyncThunk(
  "course/loadCourse",
  async ({ courseId }, { rejectWithValue }) => {
    try {
      const response = await getRegisteredCourseService({ courseId });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

const courseSlice = createSlice({
  name: "course",
  initialState: {
    courses: [],
    registeredCourses: [],
    completeQuestions: [],
    currentCourse: null,
    error: null,
    loading: "idle", // idle | pending | succeeded | failed
  },
  reducers: {},
  extraReducers: (builder) => {
    builder.addCase(insertCourse.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(insertCourse.fulfilled, (state) => {
      state.loading = "succeeded";
    });
    builder.addCase(insertCourse.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(getAvailableCourses.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getAvailableCourses.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.courses = JSON.parse(action.payload.courses);
    });
    builder.addCase(getAvailableCourses.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(getRegisteredCourses.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getRegisteredCourses.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.registeredCourses = JSON.parse(action.payload.courses);
    });
    builder.addCase(getRegisteredCourses.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(registerCourse.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(registerCourse.fulfilled, (state) => {
      state.loading = "succeeded";
    });
    builder.addCase(registerCourse.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(loadCourse.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(loadCourse.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.currentCourse = JSON.parse(action.payload.course);
    });
    builder.addCase(loadCourse.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(getCompleteQuestions.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getCompleteQuestions.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.completeQuestions = action.payload.complete_questions;
    });
    builder.addCase(getCompleteQuestions.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const {} = courseSlice.actions;
export default courseSlice.reducer;
