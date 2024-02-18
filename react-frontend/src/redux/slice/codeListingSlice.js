import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  getFileInfoService,
  disassembleBinaryService,
} from "../service/codeListingService";

export const getFileInfo = createAsyncThunk(
  "revenv/get-file-info",
  async ({ filename }, { rejectWithValue }) => {
    try {
      const response = await getFileInfoService({ filename });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const disassembleBinary = createAsyncThunk(
  "revenv/disassemble-binary",
  async ({ filename }, { rejectWithValue }) => {
    try {
      const response = await disassembleBinaryService({ filename });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

const codeListingSlice = createSlice({
  name: "codeListing",
  initialState: {
    funcPaneWidth: 0,
    disassPaneWidth: 0,
    loading: "idle", // idle | pending | succeeded | failed
    error: null,
    fileInfo: null,
    exports: [],
    imports: [],
    sections: [],
    classes: [],
    entry: [],
    symbols: [],
    strings: [],
    assembly: [],
  },
  reducers: {
    setFuncPaneWidth: (state, action) => {
      state.funcPaneWidth = action.payload;
    },
    setDisassPaneWidth: (state, action) => {
      state.disassPaneWidth = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(getFileInfo.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getFileInfo.fulfilled, (state, action) => {
      state.loading = "succeeded";
      let data = JSON.parse(action.payload.payload);
      state.fileInfo = data.i;
      state.exports = data.iE;
      state.imports = data.ii;
      state.sections = data.iS;
      state.classes = data.ic;
      state.entry = data.ie;
      state.symbols = data.is;
      state.strings = data.iz;
    });
    builder.addCase(getFileInfo.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(disassembleBinary.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(disassembleBinary.fulfilled, (state, action) => {
      state.loading = "succeeded";
      let data  = JSON.parse(action.payload.payload);
      state.assembly = data;
    });
    builder.addCase(disassembleBinary.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const { setFuncPaneWidth, setDisassPaneWidth } =
  codeListingSlice.actions;

export default codeListingSlice.reducer;
