import { configureStore } from "@reduxjs/toolkit";
import codeListingReducer from "./slice/codeListingSlice";
import sandboxReducer from "./slice/sandboxSlice";
import authReducer from "./slice/authSlice";
import sessionReducer from "./slice/sessionSlice";
import sessionMiddleware from "./middleware/socketMiddleware";

export default configureStore({
  reducer: {
    codeListing: codeListingReducer,
    sandbox: sandboxReducer,
    auth: authReducer,
    session: sessionReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      immutableCheck: { warnAfter: 128 },
      serializableCheck: { warnAfter: 128 },
    }).concat([sessionMiddleware]),
});
