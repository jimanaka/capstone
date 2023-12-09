import { createSlice } from "@reduxjs/toolkit";

const codeListingSlice = createSlice({
  name: "codeListing",
  initialState: {
    funcPaneWidth: 0,
  },
  reducers: {
    setFuncPaneWidth: (state, action) => {
      state.funcPaneWidth = action.payload;
    },
  },
});

export const { setFuncPaneWidth } = codeListingSlice.actions;

export default codeListingSlice.reducer;
