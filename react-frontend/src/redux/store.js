import { configureStore } from "@reduxjs/toolkit";
import codeListingReducer from "./slice/codeListingSlice";

export default configureStore({
  reducer: {
    codeListing: codeListingReducer,
  },
});
