import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { uploadFileService } from "../service/fileUploadService";

export const uploadFile = createAsyncThunk(
  "revenv/upload-file",
  async ({ file }, { rejectWithValue }) => {
    try {
      const response = await uploadFileService({ file });
      console.log(response.data)
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

const sandboxSlice = createSlice({
  name: "sandbox",
  initialState: {
    currentTab: 0,
    currentFilepath: null,
    loading: "idle", // idle | pending | succeeded | failed
    error: null,
  },
  reducers: {
    setCurrentTab: (state, action) => {
      state.currentTab = action.payload;
    },
    setCurrentFilepath: (state, action) => {
      state.currentFilepath = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(uploadFile.pending, (state) => {
      state.loading = "pending";
    }),
    builder.addCase(uploadFile.fulfilled, (state, action) => {
      state.loading = "succeeded";
    }),
    builder.addCase(uploadFile.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    })
  }
});

export const { setCurrentTab, setCurrentFilepath } = sandboxSlice.actions;

export default sandboxSlice.reducer;
