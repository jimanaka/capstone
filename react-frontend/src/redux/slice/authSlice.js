import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import axios from "axios";

export const loginUser = createAsyncThunk(
  "auth/register",
  async ({ username, password }, { rejectWithValue }) => {
    try {
      const config = {
        headers: {
          "Content-Type": "application/json",
        },
      };
      const response = await axios.post(
        "http://localhost:80/api/auth/login",
        { username, password },
        config,
      );
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

const authSlice = createSlice({
  name: "auth",
  initialState: {
    authToken: "",
    error: null,
    loading: "idle", // idle | pending | succeeded | failed
  },
  reducers: {},
  extraReducers: (builder) => {
    builder.addCase(loginUser.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(loginUser.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.authToken = action.payload;
    });
    builder.addCase(loginUser.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export default authSlice.reducer;
