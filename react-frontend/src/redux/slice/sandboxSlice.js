import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  uploadFileService,
  listFilesService,
  deleteFileService,
} from "../service/fileUploadService";

export const uploadFile = createAsyncThunk(
  "revenv/upload-file",
  async ({ file }, { rejectWithValue }) => {
    try {
      const response = await uploadFileService({ file });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const listFiles = createAsyncThunk(
  "revenv/list-files",
  async (_, { rejectWithValue }) => {
    try {
      const response = await listFilesService();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const deleteFile = createAsyncThunk(
  "revenv/delete-file",
  async ({ filename }, { rejectWithValue }) => {
    try {
      const response = await deleteFileService({ filename });
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
    currentFilePath: null,
    loading: "idle", // idle | pending | succeeded | failed
    error: null,
    fileList: [],
  },
  reducers: {
    setCurrentTab: (state, action) => {
      state.currentTab = action.payload;
    },
    setCurrentFilePath: (state, action) => {
      state.currentFilePath = action.payload;
    },
    setFileList: (state, action) => {
      state.fileList = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(uploadFile.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(uploadFile.fulfilled, (state, action) => {
      state.loading = "succeeded";
    });
    builder.addCase(uploadFile.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(listFiles.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(listFiles.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.fileList = action.payload.files;
    });
    builder.addCase(listFiles.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(deleteFile.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(deleteFile.fulfilled, (state, action) => {
      state.loading = "succeeded";
      const file = action.payload.file;
      const index = state.fileList.indexOf(file);
      if (index > -1) {
        state.fileList.splice(index, 1)
      }
    });
    builder.addCase(deleteFile.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const { setCurrentTab, setCurrentFilePath, setFileList } =
  sandboxSlice.actions;

export default sandboxSlice.reducer;
