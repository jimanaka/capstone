import { configureStore } from "@reduxjs/toolkit";
import codeListingReducer from "./slice/codeListingSlice";
import sandboxReducer from "./slice/sandboxSlice";

export default configureStore({
  reducer: {
    codeListing: codeListingReducer,
    sandbox: sandboxReducer,
  },
});
