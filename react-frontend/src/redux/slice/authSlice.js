import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { register, login, getCurrentUser } from "../service/authService";

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

export const verifyUser = createAsyncThunk("auth/verifyUser", async () => {
  try {
    const response = await getCurrentUser();
    return response.data;
  } catch (error) {
    console.log("error checking logins status");
  }
});

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
      localStorage.setItem("user", JSON.stringify(state.user));
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
      state.user = action.payload;
    });
    builder.addCase(verifyUser.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
      state.user = null;
    });
  },
});

export default authSlice.reducer;
