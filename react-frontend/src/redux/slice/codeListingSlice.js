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
      const response = await disassembleBinaryService({
        filename,
        direction,
        target,
        mode,
      });
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
const initialState = {
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
  bottomAddress: null,
  decompiledCode: [],
};

const codeListingSlice = createSlice({
  name: "codeListing",
  initialState,
  reducers: {
    setFuncPaneWidth: (state, action) => {
      state.funcPaneWidth = action.payload;
    },
    setDisassPaneWidth: (state, action) => {
      state.disassPaneWidth = action.payload;
    },
    setFileInfo: (state, action) => {
      state.fileInfo = action.payload;
    },
    setFunctions: (state, action) => {
      state.functions = action.payload;
    },
    setExports: (state, action) => {
      state.exports = action.payload;
    },
    setImports: (state, action) => {
      state.imports = action.payload;
    },
    setSections: (state, action) => {
      state.sections = action.payload;
    },
    setClasses: (state, action) => {
      state.classes = action.payload;
    },
    setEntry: (state, action) => {
      state.entry = action.payload;
    },
    setSymbols: (state, action) => {
      state.symbols = action.payload;
    },
    setStrings: (state, action) => {
      state.strings = action.payload;
    },
    setAssembly: (state, action) => {
      state.assembly = action.payload;
    },
    setTopAddress: (state, action) => {
      state.topAddress = action.payload;
    },
    setBotAddress: (state, action) => {
      state.bottomAddress = action.payload;
    },
    setDecompiledCode: (state, action) => {
      state.decompiledCode = action.payload;
    },
    resetCodeListingState: () => initialState,
  },
  extraReducers: (builder) => {
    builder.addCase(getFileInfo.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getFileInfo.fulfilled, (state, action) => {
      state.loading = "succeeded";
      // let data = JSON.parse(action.payload.payload);
      let data = action.payload.payload;
      // For rizin instead of r2
      // state.fileInfo = data.info;
      // state.exports = data.exports;
      // state.imports = data.imports;
      // state.sections = data.sections;
      // state.classes = data.classes;
      // state.entry = data.entries;
      // state.symbols = data.symbols;
      // state.strings = data.strings;
      // state.functions = data.afl;
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

export const {
  setFuncPaneWidth,
  setDisassPaneWidth,
  setFileInfo,
  setFunctions,
  setExports,
  setImports,
  setSections,
  setClasses,
  setEntry,
  setSymbols,
  setStrings,
  setAssembly,
  setTopAddress,
  setBotAddress,
  setDecompiledCode,
  resetCodeListingState,
} = codeListingSlice.actions;

export default codeListingSlice.reducer;
