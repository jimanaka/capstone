import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";

const payloadGeneratorSlice = createSlice({
  name: "payloadGenerator",
  initialState: {
    userChain: [],
  },
  reducers: {
    setUserChain: (state, action) => {
      state.userChain = action.payload;
    },
    addUserChain: (state, action) => {
      state.userChain.push(action.payload);
    },
  },
});

export const {
  setUserChain,
  addUserChain,
} = payloadGeneratorSlice.actions;

export default payloadGeneratorSlice.reducer;
