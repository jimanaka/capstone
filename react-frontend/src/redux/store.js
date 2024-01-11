import { configureStore } from "@reduxjs/toolkit";
import codeListingReducer from "./slice/CodeListingSlice";
import sandboxReducer from "./slice/sandboxSlice";
import authReducer from "./slice/authSlice";

export default configureStore({
  reducer: {
    codeListing: codeListingReducer,
    sandbox: sandboxReducer,
    auth: authReducer,
  },
});
