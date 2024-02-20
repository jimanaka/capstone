import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  getFileInfoService,
  disassembleBinaryService,
  decompileFunctionService,
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
  async ({ filename, direction, target, mode }, { rejectWithValue }) => {
    try {
      const response = await disassembleBinaryService({ filename, direction, target, mode });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const decompileFunction = createAsyncThunk(
  "revenv/decompile-function",
  async ({ filename, address }, { rejectWithValue }) => {
    try {
      const response = await decompileFunctionService({ filename, address });
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
    functions: [],
    exports: [],
    imports: [],
    sections: [],
    classes: [],
    entry: [],
    symbols: [],
    strings: [],
    assembly: [],
    topAddress: null,
    oldTopAddress: null,
    bottomAddress: null,
    decompiledCode: [],
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
      // let data = JSON.parse(action.payload.payload);
      let data = action.payload.payload;
      state.fileInfo = data.i;
      state.exports = data.iE;
      state.imports = data.ii;
      state.sections = data.iS;
      state.classes = data.ic;
      state.entry = data.ie;
      state.symbols = data.is;
      state.strings = data.iz;
      state.functions = data.afl;
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
      if (action.payload.mode === "refresh") {
        state.assembly = [];
      }
      // let data = JSON.parse(action.payload.payload);
      let data = action.payload.payload;
      if (action.payload.direction === "up") {
        state.assembly = data.concat(state.assembly);
      } else {
        state.assembly = state.assembly.concat(data);
      }
      state.oldTopAddress = state.topAddress;
      state.topAddress = `0x${data[0].offset.toString(16)}`;
      state.bottomAddress = `0x${data[data.length - 1].offset.toString(16)}`;
    });
    builder.addCase(disassembleBinary.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(decompileFunction.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(decompileFunction.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.decompiledCode = action.payload.payload;
    });
    builder.addCase(decompileFunction.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const { setFuncPaneWidth, setDisassPaneWidth } =
  codeListingSlice.actions;

export default codeListingSlice.reducer;
