import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { startPGService, createChainService } from "../service/payloadGeneratorService";

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

export const createChain = createAsyncThunk(
  "revenv/create-chain",
  async ({ chain }, { rejectWithValue }) => {
    try {
      const response = await createChainService({ chain });
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
    setUserChainIndexField: (state, action) => {
      console.log(action.payload);
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
    });
    builder.addCase(startPG.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
    builder.addCase(createChain.pending, (state) => {
      state.loading = "pending";
    });
    builder.addCase(createChain.fulfilled, (state, action) => {
      state.loading = "succeeded";
    });
    builder.addCase(createChain.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  }
});

export const {
  setUserChain,
  addUserChain,
  setUserChainIndexField,
  resetPayloadGeneratorState,
} = payloadGeneratorSlice.actions;

export default payloadGeneratorSlice.reducer;
