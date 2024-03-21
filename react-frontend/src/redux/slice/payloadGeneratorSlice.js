import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { startPGService, createChainService, createPayloadService } from "../service/payloadGeneratorService";

export const createPayload = createAsyncThunk(
  "revenv/create-payload",
  async ({ input }, { rejectWithValue }) => {
    try {
      console.log(input);
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
      state.userChain[action.payload.index][action.payload.field] = action.payload.value;
    },
    addUserChain: (state, action) => {
      state.userChain.push(action.payload);
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
      console.log(action.payload)
      state.payloadDump = action.payload.payload_dump;
      state.payloadHexdump = action.payload.hexdump;
    });
    builder.addCase(createPayload.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  }
});

export const {
  setUserChain,
  addUserChain,
  setUserChainIndex,
  setUserChainIndexField,
  resetPayloadGeneratorState,
} = payloadGeneratorSlice.actions;

export default payloadGeneratorSlice.reducer;
