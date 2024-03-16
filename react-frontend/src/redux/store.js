import { configureStore } from "@reduxjs/toolkit";
import codeListingReducer from "./slice/codeListingSlice";
import sandboxReducer from "./slice/sandboxSlice";
import authReducer from "./slice/authSlice";
import sessionReducer from "./slice/sessionSlice";
import courseReducer from "./slice/courseSlice";
import createCourseReducer from "./slice/createCourseSlice"
import sessionMiddleware from "./middleware/socketMiddleware";
import payloadGeneratorReducer from "./slice/payloadGenerator";

export default configureStore({
  reducer: {
    codeListing: codeListingReducer,
    sandbox: sandboxReducer,
    auth: authReducer,
    session: sessionReducer,
    course: courseReducer,
    createCourse: createCourseReducer,
    payloadGenerator: payloadGeneratorReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      immutableCheck: { warnAfter: 128 },
      serializableCheck: { warnAfter: 128 },
    }).concat([sessionMiddleware]),
});
