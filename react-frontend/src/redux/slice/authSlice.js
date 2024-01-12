import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  register,
  login,
  getCurrentUser,
  logout,
} from "../service/authService";

export const registerUser = createAsyncThunk(
  "auth/register",
  async ({ username, email, password }, { rejectWithValue }) => {
    try {
      const response = await register({ username, email, password });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const loginUser = createAsyncThunk(
  "auth/login",
  async ({ username, password }, { rejectWithValue }) => {
    try {
      const response = await login({ username, password });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const logoutUser = createAsyncThunk(
  "token/logout",
  // eslint-disable-next-line no-unused-vars
  async (_, { rejectWithValue }) => {
    try {
      const response = await logout();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const verifyUser = createAsyncThunk(
  "auth/verifyUser",
  // eslint-disable-next-line no-unused-vars
  async (_, { rejectWithValue }) => {
    try {
      const response = await getCurrentUser();
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
    user: null,
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
      state.user = action.payload;
    });
    builder.addCase(loginUser.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
      state.user = null;
    });
    builder.addCase(verifyUser.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(verifyUser.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.user = action.payload.logged_in_as;
    });
    builder.addCase(verifyUser.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
      state.user = null;
    });
    builder.addCase(logoutUser.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(logoutUser.fulfilled, (state) => {
      state.loading = "succeeded";
      state.user = null;
    });
    builder.addCase(logoutUser.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export default authSlice.reducer;
