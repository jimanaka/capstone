import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import { disassembleBinaryService } from "../service/codeListingService";

export const disassembleBinary = createAsyncThunk(
  "revenv/disassemble-binary",
  async({ filename }, { rejectWithValue }) => {
    try {
      const response = await disassembleBinaryService({ filename });
      return response.data;
    } catch (error) {
      if (error.response && error.response.data.message) {
        return rejectWithValue(error.response.data.message);
      }
      return rejectWithValue(error.message);
    }
  }
);

const codeListingSlice = createSlice({
  name: "codeListing",
  initialState: {
    funcPaneWidth: 0,
    disassPaneWidth: 0,
    loading: "idle", // idle | pending | succeeded | failed
    error: null,
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
    builder.addCase(disassembleBinary.pending, (state) => {
      state.loading = "pending";
    }),
    builder.addCase(disassembleBinary.fulfilled, (state, action) => {
      state.loading = "succeeded";
      console.log(action.payload)
    });
    builder.addCase(disassembleBinary.rejected, (state, action) => {
      state.loading = "failed";
      state.error = action.payload;
    });
  }
});

export const { setFuncPaneWidth, setDisassPaneWidth } =
  codeListingSlice.actions;

export default codeListingSlice.reducer;
