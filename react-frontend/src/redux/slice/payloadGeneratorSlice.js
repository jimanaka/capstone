import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
  startPGService,
  createPayloadService,
  usePayloadService,
  getPayloadCodeService,
  getByteStringService,
} from "../service/payloadGeneratorService";

export const createPayload = createAsyncThunk(
  "revenv/create-payload",
  async ({ input }, { rejectWithValue }) => {
    try {
      const response = await createPayloadService({ input });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const getPayloadCode = createAsyncThunk(
  "revenv/get-byte-string",
  async (_, { rejectWithValue }) => {
    try {
      const response = await getPayloadCodeService();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const getByteString = createAsyncThunk(
  "revenv/get-payload-code",
  async (_, { rejectWithValue }) => {
    try {
      const response = await getByteStringService();
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const usePayload = createAsyncThunk(
  "revenv/use-payload",
  async ({ pid }, { rejectWithValue }) => {
    try {
      const response = await usePayloadService({ pid });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  },
);

export const startPG = createAsyncThunk(
  "revenv/start-pg",
  async ({ filePath }, { rejectWithValue }) => {
    try {
      const response = await startPGService({ filePath });
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
  loading: "idle", // idle | pending | succeeded | failed
  error: null,
  userChain: [],
  simpleGadgets: [],
  availableRegs: [],
  payloadDump: "",
  payloadHexdump: "",
  currentInputs: {},
  payloadCode: "",
  byteString: "",
};

const payloadGeneratorSlice = createSlice({
  name: "payloadGenerator",
  initialState,
  reducers: {
    setUserChain: (state, action) => {
      state.userChain = action.payload;
    },
    setUserChainIndex: (state, action) => {
      state.userChain[action.payload.index] = action.payload.chain;
    },
    setUserChainIndexField: (state, action) => {
      state.userChain[action.payload.index][action.payload.field] =
        action.payload.value;
    },
    addUserChain: (state, action) => {
      state.userChain.push(action.payload);
    },
    removeUserChainIndex: (state, action) => {
      state.userChain.splice(action.payload, 1);
    },
    addArg: (state, action) => {
      state.userChain[action.payload.index].args.push({
        arg: "",
        subtype: "numeric",
      });
    },
    setArgSubtype: (state, action) => {
      state.userChain[action.payload.index].args[
        action.payload.argIndex
      ].subtype = action.payload.value;
    },
    setCurrentInputs: (state, action) => {
      state.currentInputs = action.payload;
    },
    setPayloadDump: (state, action) => {
      state.payloadDump = action.payload;
    },
    setPayloadHexDump: (state, action) => {
      state.payloadHexdump = action.payload;
    },
    setPayloadCode: (state, action) => {
      state.payloadCode = action.payload;
    },
    setByteString: (state, action) => {
      state.byteString = action.payload;
    },
    resetPayloadGeneratorState: (state) => initialState,
  },
  extraReducers: (builder) => {
    builder.addCase(startPG.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(startPG.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.simpleGadgets = action.payload["simple_gadgets"];
      state.availableRegs = action.payload["available_regs"];
    });
    builder.addCase(startPG.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(createPayload.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(createPayload.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.payloadDump = action.payload.payload_dump;
      state.payloadHexdump = action.payload.hexdump;
    });
    builder.addCase(createPayload.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(getPayloadCode.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getPayloadCode.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.payloadCode = action.payload.code;
    });
    builder.addCase(getPayloadCode.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(getByteString.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(getByteString.fulfilled, (state, action) => {
      state.loading = "succeeded";
      state.byteString = action.payload.byteString;
    });
    builder.addCase(getByteString.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  },
});

export const {
  setUserChain,
  addUserChain,
  setUserChainIndex,
  setUserChainIndexField,
  resetPayloadGeneratorState,
  addArg,
  setArgSubtype,
  setCurrentInputs,
  removeUserChainIndex,
  setPayloadDump,
  setPayloadHexDump,
  setPayloadCode,
  setByteString,
} = payloadGeneratorSlice.actions;

export default payloadGeneratorSlice.reducer;
