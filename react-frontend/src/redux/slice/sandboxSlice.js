import { createSlice } from "@reduxjs/toolkit";

const sandboxSlice = createSlice({
  name: "sandbox",
  initialState: {
    currentTab: 0,
  },
  reducers: {
    setCurrentTab: (state, action) => {
      state.currentTab = action.payload;
    },
  },
});

export const { setCurrentTab } = sandboxSlice.actions;

export default sandboxSlice.reducer;
