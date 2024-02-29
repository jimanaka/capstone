import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  uploadFileService,
  listFilesService,
} from "../service/fileUploadService";

export const uploadFile = createAsyncThunk(
  "revenv/upload-file",
  async ({ file }, { rejectWithValue }) => {
    try {
      const response = await uploadFileService({ file });
      console.log(response.data);
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
      console.log("getting filse")
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

const sandboxSlice = createSlice({
  name: "sandbox",
  initialState: {
    currentTab: 0,
    currentFilepath: null,
    loading: "idle", // idle | pending | succeeded | failed
    error: null,
    fileList: [],
  },
  reducers: {
    setCurrentTab: (state, action) => {
      state.currentTab = action.payload;
    },
    setCurrentFilepath: (state, action) => {
      state.currentFilepath = action.payload;
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
      state.fileList = action.payload.files
    });
    builder.addCase(listFiles.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const { setCurrentTab, setCurrentFilepath, setFileList } = sandboxSlice.actions;

export default sandboxSlice.reducer;
