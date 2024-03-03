import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { insertCourseService, listAvailableCoursesService } from "../service/courseService";

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

export const listAvailableCourses = createAsyncThunk(
  "course/listAvailableCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await listAvailableCoursesService();
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
    builder.addCase(listAvailableCourses.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(listAvailableCourses.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.courses = JSON.parse(action.payload.courses);
    });
    builder.addCase(listAvailableCourses.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const {} = courseSlice.actions;
export default courseSlice.reducer;
