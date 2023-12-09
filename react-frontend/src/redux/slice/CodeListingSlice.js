import { createSlice } from "@reduxjs/toolkit";

const codeListingSlice = createSlice({
  name: "codeListing",
  initialState: {
    funcPaneWidth: 0,
    disassPaneWidth: 0,
  },
  reducers: {
    setFuncPaneWidth: (state, action) => {
      state.funcPaneWidth = action.payload;
    },
    setDisassPaneWidth: (state, action) => {
      state.disassPaneWidth = action.payload;
    },
  },
});

export const { setFuncPaneWidth, setDisassPaneWidth } =
  codeListingSlice.actions;

export default codeListingSlice.reducer;
